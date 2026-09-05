@echo off
rem ============================================================================
rem  build.bat - GhidraMCP one-click clean/compile/test/package/install
rem
rem  Self-contained entry point. Depends on a local JDK 21+ and a Ghidra install.
rem  The PowerShell build engine is embedded below the batch marker line;
rem  this batch portion extracts it to a temp .ps1 and runs it with pwsh
rem  (falling back to Windows PowerShell if pwsh is not on PATH).
rem
rem  Usage: build.bat [phase]   phases: all | clean | compile | test | package | install
rem ============================================================================
setlocal
set "GMCP_BAT=%~f0"
set "GMCP_PHASES=%*"
if "%GMCP_PHASES%"=="" set "GMCP_PHASES=all"

where pwsh >nul 2>nul
if errorlevel 1 set "GMCP_PSH=powershell"
if not errorlevel 1 set "GMCP_PSH=pwsh"

%GMCP_PSH% -NoProfile -ExecutionPolicy Bypass -Command "$tok='#@GMCP_PWSH_BODY'+'@#'; $s=[IO.File]::ReadAllText($env:GMCP_BAT); $i=$s.IndexOf($tok); $b=$s.Substring($i+$tok.Length); $t=Join-Path $env:TEMP ('gmcp_build_' + [guid]::NewGuid().ToString('N') + '.ps1'); [IO.File]::WriteAllText($t, $b, [Text.UTF8Encoding]::new($false)); & $t $env:GMCP_PHASES; $c=$LASTEXITCODE; Remove-Item $t -ErrorAction SilentlyContinue; exit $c"
exit /b %ERRORLEVEL%
#@GMCP_PWSH_BODY@#
# =============================================================================
#  GhidraMCP build engine (embedded below the batch marker line)
# =============================================================================

param(
    [string]$Phase = "all"
)

$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8

$Root = Split-Path -Parent $env:GMCP_BAT
# pwsh 7 names it "UTF-8"; Windows PowerShell 5.1 requires the enum "UTF8".
$Encode = $(if ($PSVersionTable.PSVersion.Major -ge 7) { "UTF-8" } else { "UTF8" })
# javac @argfile rejects a leading UTF-8 BOM (breaks the first source path);
# Set-Content -Encoding UTF-8 writes a BOM on pwsh 7, so argfiles use no-BOM.
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Fail([string]$msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Locate JDK (JDK 21+ required; we compile with --release 21).
# ---------------------------------------------------------------------------
function Find-Jdk {
    foreach ($c in @("$env:JAVA_HOME", "D:\jdk\jdk-26", "D:\jdk\jdk-25.0.2")) {
        if ($c -and (Test-Path "$c\bin\javac.exe")) { return $c }
    }
    foreach ($c in @("C:\Program Files\Java", "C:\Program Files\Eclipse Adoptium")) {
        if (Test-Path $c) {
            $hit = Get-ChildItem $c -Directory | Sort-Object Name -Descending |
                   Where-Object { Test-Path "$($_.FullName)\bin\javac.exe" } | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Locate Ghidra install (auto-detect newest PUBLIC under common parents).
# ---------------------------------------------------------------------------
function Find-Ghidra {
    foreach ($p in @("$env:GHIDRA_PATH", "D:\crack\ghidra", "F:\ghidra_12.1.2_PUBLIC")) {
        if (-not $p -or -not (Test-Path $p)) { continue }
        if (Test-Path "$p\Ghidra\application.properties") { return $p }
        $hit = Get-ChildItem $p -Directory | Where-Object { Test-Path "$($_.FullName)\Ghidra\application.properties" } |
               Sort-Object Name -Descending | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

function Read-PomVersion {
    $pom = Join-Path $Root "pom.xml"
    $xml = [xml](Get-Content $pom -Raw -Encoding $Encode)
    return $xml.project.version
}

function Get-GhidraInstallMeta {
    param([string]$GhidraPath)
    $props = Join-Path $GhidraPath "Ghidra\application.properties"
    $version = ""
    $layout = "PUBLIC"
    if (Test-Path $props) {
        $lines = Get-Content $props -Encoding $Encode
        foreach ($l in $lines) {
            if ($l -match "^\s*application\.version=(.+)$")   { $version = $Matches[1].Trim() }
            if ($l -match "^\s*application\.release\.name=(.+)$") { $layout = $Matches[1].Trim() }
        }
    }
    return @{ Version = $version; Layout = $layout }
}

$Jdk   = Find-Jdk
$Ghidra = Find-Ghidra
if (-not $Jdk)   { Fail "No JDK found. Set JAVA_HOME or install JDK 21+." }
if (-not $Ghidra) { Fail "No Ghidra install found. Set GHIDRA_PATH." }

$Version    = Read-PomVersion
$Meta       = Get-GhidraInstallMeta $Ghidra
$GhidraVer  = $Meta.Version
$BuildTs    = Get-Date -Format "yyyyMMdd-HHmmss"

$MainSrc   = Join-Path $Root "src\main\java"
$ResSrc    = Join-Path $Root "src\main\resources"
$BuildDir  = Join-Path $Root "build"
$DistDir   = Join-Path $Root "dist"
$Classes   = Join-Path $BuildDir "classes"
$ResOut    = Join-Path $BuildDir "resources"
$TestSrc   = Join-Path $Root "src\test\java\com\xebyte\offline"
$TestCls   = Join-Path $BuildDir "test-classes"
$CfgDir    = Join-Path $BuildDir "config"
$CpFile    = Join-Path $CfgDir "classpath.txt"

$Javac = Join-Path $Jdk "bin\javac.exe"
$Java  = Join-Path $Jdk "bin\java.exe"
$Jar   = Join-Path $Jdk "bin\jar.exe"
if (-not (Test-Path $Javac)) { Fail "javac not found under $Jdk" }

$JunitHome   = Join-Path $env:USERPROFILE ".m2\repository\junit\junit\4.13.2"
$JunJar      = Join-Path $JunitHome "junit-4.13.2.jar"
$HamcrestJar = Join-Path $env:USERPROFILE ".m2\repository\org\hamcrest\hamcrest-core\1.3\hamcrest-core-1.3.jar"

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
function Invoke-Clean {
    Write-Step "Clean"
    foreach ($p in @($BuildDir, $DistDir, (Join-Path $Root ".pytest_cache"), (Join-Path $Root "junit.xml"))) {
        if (Test-Path $p) {
            Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue
            Write-Host "  removed: $p"
        }
    }
}

# ---------------------------------------------------------------------------
# classpath: every jar shipped under the Ghidra install
# ---------------------------------------------------------------------------
function Get-GhidraClasspath {
    $jars = @()
    foreach ($land in @("Framework", "Features", "Debug", "Processors")) {
        $dir = Join-Path $Ghidra "Ghidra\$land"
        if (Test-Path $dir) {
            $jars += Get-ChildItem $dir -Recurse -Filter *.jar | ForEach-Object { $_.FullName }
        }
    }
    return ($jars | Sort-Object -Unique) -join ";"
}

# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------
function Invoke-Compile {
    Write-Step "Compile"
    New-Item -ItemType Directory -Force -Path $Classes | Out-Null
    New-Item -ItemType Directory -Force -Path $CfgDir  | Out-Null

    $cp = Get-GhidraClasspath
    [System.IO.File]::WriteAllText($CpFile, $cp, $Utf8NoBom)
    Write-Host "  classpath jars: $($cp.Split(';').Count)"

    $srcs = Get-ChildItem $MainSrc -Recurse -Filter *.java | ForEach-Object { $_.FullName }
    New-Item -ItemType Directory -Force -Path (Join-Path $BuildDir "src-list") | Out-Null
    $srcListFile = Join-Path $BuildDir "src-list\main-srcs.txt"
    [System.IO.File]::WriteAllText($srcListFile, ($srcs -join "`n"), $Utf8NoBom)

    & $Javac --release 21 -encoding $Encode -proc:none -cp $cp -d $Classes @$srcListFile
    if ($LASTEXITCODE -ne 0) { Fail "javac failed (exit $LASTEXITCODE)" }
    Write-Host "  compiled $($srcs.Count) sources to $Classes"
}

# ---------------------------------------------------------------------------
# Test: EndpointsJsonParityTest (offline Java) + Python unit tests
# ---------------------------------------------------------------------------
function Invoke-Test {
    Write-Step "Test"
    if (-not (Test-Path $Classes)) {
        Write-Host "  (no classes yet -- running compile first)"
        Invoke-Compile
    }
    if (-not (Test-Path $JunJar)) {
        Write-Host "  WARN: junit not at $JunJar -- skipping Java parity test"
    } else {
        New-Item -ItemType Directory -Force -Path $TestCls | Out-Null
        $cp = Get-Content $CpFile -Raw
        $testCp = "$cp;$Classes;$JunJar;$HamcrestJar"
        $tSrcs = @(
            (Join-Path $TestSrc "EndpointsJsonParityTest.java"),
            (Join-Path $TestSrc "ServiceFactory.java"),
            (Join-Path $TestSrc "StubProgramProvider.java"),
            (Join-Path $TestSrc "NoopThreadingStrategy.java")
        )
        $tList = Join-Path $BuildDir "src-list\test-srcs.txt"
        [System.IO.File]::WriteAllText($tList, ($tSrcs -join "`n"), $Utf8NoBom)
        & $Javac --release 21 -encoding $Encode -proc:none -cp $testCp -d $TestCls @$tList
        if ($LASTEXITCODE -ne 0) { Fail "test javac failed (exit $LASTEXITCODE)" }

        Push-Location $Root
        & $Java -cp "$testCp;$TestCls" org.junit.runner.JUnitCore com.xebyte.offline.EndpointsJsonParityTest 2>&1 | Tee-Object -Variable parityOut
        $parityExit = $LASTEXITCODE
        Pop-Location
        if ($parityExit -ne 0) { Fail "EndpointsJsonParityTest failed (exit $parityExit)" }
        if (($parityOut -join "`n") -notmatch "\bOK\b") { Fail "EndpointsJsonParityTest did not report OK" }
    }

    if (Get-Command uv -ErrorAction SilentlyContinue) {
        Push-Location $Root
        $env:PYTHONUTF8 = "1"
        $env:PYTHONIOENCODING = "utf-8"
        uv run --frozen python -m pytest tests/unit -q --no-cov --deselect "tests/unit/test_gradle_tasks.py"
        $pyExit = $LASTEXITCODE
        Pop-Location
        if ($pyExit -ne 0) { Fail "pytest failed (exit $pyExit)" }
    } else {
        Write-Host "  WARN: uv not found -- skipping Python tests"
    }
}

# ---------------------------------------------------------------------------
# Package: filtered resources -> jar -> extension zip under dist/
# ---------------------------------------------------------------------------
function Invoke-Package {
    Write-Step "Package"
    if (-not (Test-Path $Classes)) { Invoke-Compile }

    # 1. Filter resources (extension.properties / version.properties token substitution)
    if (Test-Path $ResOut) { Remove-Item -Recurse -Force $ResOut }
    Copy-Item -Recurse -Force $ResSrc $ResOut

    $tokenMap = @{
        '${project.version}' = $Version
        '${ghidra.version}'  = $GhidraVer
        '${build.timestamp}' = $BuildTs
        '${build.number}'    = $BuildTs
    }
    foreach ($file in @((Join-Path $ResOut "extension.properties"),
                        (Join-Path $ResOut "com\xebyte\version.properties"))) {
        if (-not (Test-Path $file)) { continue }
        $text = Get-Content $file -Raw -Encoding $Encode
        foreach ($k in $tokenMap.Keys) { $text = $text.Replace($k, $tokenMap[$k]) }
        [System.IO.File]::WriteAllText($file, $text, $Utf8NoBom)
    }

    # 2. Jar
    New-Item -ItemType Directory -Force -Path (Join-Path $BuildDir "jar") | Out-Null
    $jarPath = Join-Path $BuildDir "jar\GhidraMCP-$Version.jar"

    # Manifest (gradle-style, dynamic; excludes static src resource copy)
    $manifest = @(
        "Manifest-Version: 1.0",
        "Plugin-Class: com.xebyte.GhidraMCPPlugin",
        "Plugin-Name: GhidraMCP",
        "Plugin-Version: $Version",
        "Plugin-Author: Ben Ethington",
        "Plugin-Description: GhidraMCP - HTTP server plugin with MCP tools for reverse engineering automation",
        ""
    )
    New-Item -ItemType Directory -Force -Path $CfgDir | Out-Null
    $manFile = Join-Path $CfgDir "MANIFEST.MF"
    [System.IO.File]::WriteAllText($manFile, ($manifest -join "`r`n"), $Utf8NoBom)

    Push-Location $BuildDir
    # jar cfm <out> <manifest> -C classes . -C resources . (skip static META-INF/MANIFEST.MF)
    & $Jar cfm $jarPath $manFile -C $Classes . -C $ResOut .
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "jar failed (exit $LASTEXITCODE)" }
    Pop-Location
    Write-Host "  jar: $jarPath ($((Get-Item $jarPath).Length) bytes)"

    # 3. Extension zip -> dist/
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $zipPath = Join-Path $DistDir "GhidraMCP-$Version.zip"
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }

    $stage = Join-Path $BuildDir "stage\GhidraMCP"
    if (Test-Path (Join-Path $BuildDir "stage")) { Remove-Item -Recurse -Force (Join-Path $BuildDir "stage") }
    New-Item -ItemType Directory -Force -Path (Join-Path $stage "lib") | Out-Null
    Copy-Item (Join-Path $ResOut "extension.properties") $stage
    Copy-Item (Join-Path $ResSrc "Module.manifest")        (Join-Path $stage "Module.manifest")
    Copy-Item $jarPath (Join-Path $stage "lib")

    Push-Location (Join-Path $BuildDir "stage")
    Compress-Archive -Path "GhidraMCP\*" -DestinationPath $zipPath -CompressionLevel Optimal -Force
    Pop-Location
    if (-not (Test-Path $zipPath)) { Fail "zip creation failed" }
    Write-Host "  zip: $zipPath ($((Get-Item $zipPath).Length) bytes)"
}

# ---------------------------------------------------------------------------
# Install: copy zip into ghira Extensions/Ghidra + extract to user extension dir
# ---------------------------------------------------------------------------
function Invoke-Install {
    Write-Step "Install"
    $version = Read-PomVersion
    $zipName = "GhidraMCP-$version.zip"
    $zipPath = Join-Path $DistDir $zipName
    if (-not (Test-Path $zipPath)) { Fail "No built zip at $zipPath -- run package first" }

    # a) System extension dir (place the .zip; Ghidra picks it up on next start)
    $extDir = Join-Path $Ghidra "Extensions\Ghidra"
    New-Item -ItemType Directory -Force -Path $extDir | Out-Null
    foreach ($old in @(Get-ChildItem $extDir -Filter "GhidraMCP*.zip" -ErrorAction SilentlyContinue)) {
        Remove-Item -Force $old.FullName -ErrorAction SilentlyContinue
        Write-Host "  removed stale: $($old.Name)"
    }
    Copy-Item $zipPath $extDir -Force
    Write-Host "  installed extension zip: $extDir\$zipName"

    # b) User extension dir (extract so no GUI "install extension" is needed)
    $userBase = Join-Path $env:APPDATA "ghidra"
    if ($GhidraVer) {
        $userDir = Join-Path $userBase "ghidra_${GhidraVer}_$($Meta.Layout)"
    } else {
        $userDir = Join-Path $userBase "ghidra_${GhidraVer}_PUBLIC"
        $userDir = Join-Path $userBase ($userDir | Split-Path -Leaf)
    }
    $userExt = Join-Path $userDir "Extensions\GhidraMCP"
    New-Item -ItemType Directory -Force -Path (Join-Path $userDir "Extensions") | Out-Null
    if (Test-Path $userExt) { Remove-Item -Recurse -Force $userExt }
    New-Item -ItemType Directory -Force -Path (Join-Path $userExt "lib") | Out-Null

    Copy-Item (Join-Path $DistDir "GhidraMCP-*") $userExt -Force -ErrorAction SilentlyContinue
    # Extract jar/lib + properties from the extension zip into the user dir
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        foreach ($entry in $zip.Entries) {
            $rel = $entry.FullName -replace '^GhidraMCP/', ''
            if ([string]::IsNullOrEmpty($rel) -or $entry.FullName.EndsWith('/')) { continue }
            $dest = Join-Path $userExt $rel.Replace('/', '\')
            New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
        }
    } finally {
        $zip.Dispose()
    }
    Write-Host "  extracted user extension: $userExt"

    # c) Copy the plugin jar to ghira's user lib so analysis tools see it via extension.properties
    Write-Host "  installed to Ghidra $Ghidra (extension auto-loaded on next start; no GUI install required)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$valid = @("all", "clean", "compile", "test", "package", "install")
if ($valid -notcontains $Phase.ToLower()) {
    Fail ("Unknown phase '$Phase'. Valid: " + ($valid -join ", "))
}

Write-Host "=============================================================="
Write-Host "  GhidraMCP build ($Phase)"
Write-Host "  version : $Version"
Write-Host "  jdk     : $Jdk"
Write-Host "  ghidra  : $Ghidra ($GhidraVer $($Meta.Layout))"
Write-Host "=============================================================="

switch ($Phase.ToLower()) {
    "all"     { Invoke-Clean; Invoke-Compile; Invoke-Test; Invoke-Package; Invoke-Install }
    "clean"   { Invoke-Clean }
    "compile" { Invoke-Compile }
    "test"    { Invoke-Test }
    "package" { Invoke-Package }
    "install" { Invoke-Install }
}

Write-Host ""
Write-Host "Completed: $Phase" -ForegroundColor Green
exit 0