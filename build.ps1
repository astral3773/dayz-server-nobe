param(
    [ValidateSet("Debug", "Release")]
    [string]$build_type = "Release"
)

$ErrorActionPreference = "Stop"
$cmake_path = "cmake"

if (-not (Get-Command $cmake_path -ErrorAction SilentlyContinue)) {
    $vs_where = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vs_where) {
        $vs_path = & $vs_where -latest -products * -property installationPath
        $cmake_path = Join-Path $vs_path "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    }
    if (-not (Test-Path $cmake_path)) {
        throw "Install CMake or the Visual Studio C++ CMake tools."
    }
}

$build_dir = Join-Path $PSScriptRoot "build"

& $cmake_path -S $PSScriptRoot -B $build_dir "-DCMAKE_BUILD_TYPE=$build_type"
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $cmake_path --build $build_dir --config $build_type --parallel
exit $LASTEXITCODE
