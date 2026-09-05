"""
Gradle task registration smoke tests.

These tests invoke the Gradle wrapper (./gradlew) via subprocess to verify
custom tasks are registered and the build configuration is parseable without
requiring GHIDRA_INSTALL_DIR.  They are intentionally slow — deselect with
`-m "not slow"`.
"""
from __future__ import annotations

import functools
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GRADLEW = REPO_ROOT / ("gradlew.bat" if sys.platform == "win32" else "gradlew")


@functools.lru_cache(maxsize=1)
def _gradlew_probe_rc() -> int:
    """Run `gradlew --version` once per session; rc!=0 means the wrapper
    itself cannot start (no JDK / undownloadable distribution)."""
    return _run_gradlew("--version").returncode


@pytest.fixture(autouse=True)
def _gradle_usable():
    if shutil.which("java") is None and _find_java_home() is None:
        pytest.skip("no JDK found (set JAVA_HOME or install to D:\\jdk / Program Files\\Java)")
    # Gradle bootstrap needs to fetch its distribution over TLS; on locked-down
    # networks (PKIX failures) or offline boxes the wrapper can't start at all.
    # The canonical build path is build.bat (javac, no gradle), so treat an
    # unusable wrapper as an environment skip, like the other platform guards.
    if _gradlew_probe_rc() != 0:
        pytest.skip("gradlew unusable in this environment (distribution bootstrap failed)")


def _find_java_home() -> str | None:
    """Locate a JDK for the gradlew subprocess.

    gradlew.bat exits rc=9009 when neither JAVA_HOME nor a PATH java exists
    (a bare CI/shell on Windows), and the repo's own build.bat compensates
    with the same probe list. Mirror it: inherit JAVA_HOME when valid, else
    PATH, else common JDK install roots (newest first)."""
    candidates: list[str] = []
    env_home = os.environ.get("JAVA_HOME", "")
    if env_home and (Path(env_home) / "bin" / "java.exe").exists():
        return env_home
    if shutil.which("java"):
        return None  # gradlew finds it via PATH on its own
    for root in ("D:\\jdk", "C:\\Program Files\\Java",
                 "C:\\Program Files\\Eclipse Adoptium"):
        base = Path(root)
        if base.is_dir():
            candidates.extend(
                str(p) for p in sorted(base.iterdir(), reverse=True)
                if (p / "bin" / "java.exe").exists()
            )
    return candidates[0] if candidates else None


def _gradlew_env() -> dict[str, str] | None:
    java_home = _find_java_home()
    if java_home is None:
        return None  # None = inherit parent env unchanged
    env = dict(os.environ)
    env["JAVA_HOME"] = java_home
    return env


def _run_gradlew(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    # errors="replace": the Gradle/JVM console stream on zh-CN Windows is GBK,
    # while Python decodes it as UTF-8 — undecodable banner bytes must not kill
    # the reader thread. Assertions below only match ASCII task/version text.
    return subprocess.run(
        [str(GRADLEW), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=_gradlew_env(),
    )


@pytest.mark.slow
def test_gradlew_tasks_lists_all_custom_tasks():
    """All custom GhidraMCP tasks must appear in `./gradlew tasks --all`."""
    result = _run_gradlew("tasks", "--all")

    assert result.returncode == 0, (
        f"./gradlew tasks --all failed (rc={result.returncode}):\n{result.stderr}"
    )

    expected = [
        "buildExtension",
        "prepareGhidraClasspath",
        "verifyVersion",
        "preflight",
        "deployExtension",
        "installUserExtension",
        "patchGhidraUserConfig",
        "stopGhidra",
        "deploy",
        "startGhidra",
        "cleanAll",
    ]
    missing = [t for t in expected if t not in result.stdout]
    assert not missing, f"Custom Gradle tasks not found in task list: {missing}"


@pytest.mark.slow
def test_gradlew_deploy_task_order():
    """`./gradlew deploy --dry-run` must schedule stopGhidra before any
    write-into-Ghidra task, and patchGhidraUserConfig after the extension
    is installed. Without the stop, Windows holds a file lock on
    GhidraMCP-*.jar (install fails) and Ghidra rewrites FrontEndTool.xml
    on exit (config patch silently discarded)."""
    result = _run_gradlew("deploy", "--dry-run", "-PGHIDRA_INSTALL_DIR=nonexistent")
    assert result.returncode == 0, (
        f"deploy --dry-run failed:\n{result.stdout}\n{result.stderr}"
    )
    plan = [
        ln.split()[0].lstrip(":")
        for ln in result.stdout.splitlines()
        if ln.startswith(":")
    ]

    def idx(t):
        assert t in plan, f"task :{t} not in deploy plan: {plan}"
        return plan.index(t)

    assert idx("stopGhidra") < idx("deployExtension")
    assert idx("stopGhidra") < idx("installUserExtension")
    assert idx("stopGhidra") < idx("patchGhidraUserConfig")
    assert idx("installUserExtension") < idx("patchGhidraUserConfig"), (
        "config patch must run AFTER extension is installed"
    )


@pytest.mark.slow
def test_gradlew_verify_version_without_ghidra_dir():
    """verifyVersion should succeed without GHIDRA_INSTALL_DIR (prints skip message)."""
    import os

    env = {k: v for k, v in os.environ.items() if k != "GHIDRA_INSTALL_DIR"}
    java_home = _find_java_home()
    if java_home is not None:
        env["JAVA_HOME"] = java_home
    result = subprocess.run(
        [str(GRADLEW), "verifyVersion"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
    )

    assert result.returncode == 0, (
        f"verifyVersion failed without GHIDRA_INSTALL_DIR:\n{result.stdout}\n{result.stderr}"
    )
    combined = result.stdout + result.stderr
    assert "Project version" in combined or "skip" in combined.lower()


@pytest.mark.slow
def test_gradlew_build_extension_dry_run():
    """./gradlew buildExtension --dry-run prints the task plan without building."""
    result = _run_gradlew("buildExtension", "--dry-run", "-PGHIDRA_INSTALL_DIR=nonexistent")

    # --dry-run succeeds (rc=0) even with a bogus GHIDRA_INSTALL_DIR because
    # doLast blocks are skipped; only the task graph is printed.
    assert result.returncode == 0, (
        f"buildExtension --dry-run failed:\n{result.stdout}\n{result.stderr}"
    )
    assert "buildExtension" in result.stdout


@pytest.mark.slow
def test_gradlew_reads_version_from_pom():
    """The build script must parse pom.xml and expose the project version."""
    result = _run_gradlew("properties", "--property", "version")

    assert result.returncode == 0, (
        f"./gradlew properties failed:\n{result.stderr}"
    )
    # pom.xml contains a semver version — verify it's read
    import re
    assert re.search(r"version: \d+\.\d+\.\d+", result.stdout), (
        f"No semver found in 'version' property output:\n{result.stdout}"
    )
