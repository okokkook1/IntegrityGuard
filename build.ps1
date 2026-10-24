param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\..\work\build'),
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$guardBuildPath = [System.IO.Path]::GetFullPath($BuildDirectory)
$guardDependencies = Join-Path $guardBuildPath 'dependencies'
New-Item -ItemType Directory -Force -Path $guardBuildPath | Out-Null
& $Python -m pip install --target $guardDependencies pyinstaller==6.22.3 blake3==1.0.10
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller 安裝失敗' }
$guardOldPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = $guardDependencies
    & $Python -m PyInstaller --noconfirm --clean --onefile --windowed --name IntegrityGuard --distpath $PSScriptRoot --workpath (Join-Path $guardBuildPath 'pyinstaller') --specpath $guardBuildPath (Join-Path $PSScriptRoot 'integrity_guard.py')
    if ($LASTEXITCODE -ne 0) { throw '執行檔建置失敗' }
} finally {
    $env:PYTHONPATH = $guardOldPythonPath
}
