$ErrorActionPreference = "Stop"

$repo = if ($env:DEBUN_INSTALL_REPO) {
    $env:DEBUN_INSTALL_REPO
} else {
    "iivankin/debun"
}

$installDir = if ($env:DEBUN_INSTALL_DIR) {
    $env:DEBUN_INSTALL_DIR
} else {
    Join-Path $HOME ".local\bin"
}

$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    "X64" { "x86_64" }
    "Arm64" { "arm64" }
    default { throw "unsupported architecture: $($_.ToString())" }
}

$asset = "debun-windows-$arch.zip"

switch ($asset) {
    "debun-windows-x86_64.zip" { }
    default { throw "no published binary for windows-$arch" }
}

$url = "https://github.com/$repo/releases/latest/download/$asset"
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("debun-install-" + [System.Guid]::NewGuid().ToString("N"))
$archivePath = Join-Path $tmpDir $asset
$binaryPath = Join-Path $installDir "debun.exe"

function Add-InstallDirToUserPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PathToAdd
    )

    $currentUserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    $pathEntries = @()

    if ($currentUserPath) {
        $pathEntries = $currentUserPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
    }

    $alreadyPresent = $pathEntries | Where-Object {
        $_.TrimEnd('\').ToLowerInvariant() -eq $PathToAdd.TrimEnd('\').ToLowerInvariant()
    }

    if ($alreadyPresent) {
        return $false
    }

    $updatedUserPath = if ($currentUserPath) {
        "$currentUserPath;$PathToAdd"
    } else {
        $PathToAdd
    }

    [Environment]::SetEnvironmentVariable("Path", $updatedUserPath, [EnvironmentVariableTarget]::User)
    return $true
}

try {
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    Write-Host "downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $archivePath

    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Expand-Archive -Path $archivePath -DestinationPath $tmpDir -Force
    Copy-Item (Join-Path $tmpDir "debun.exe") $binaryPath -Force

    $pathUpdated = Add-InstallDirToUserPath -PathToAdd $installDir

    Write-Host "installed debun to $binaryPath"
    if ($pathUpdated) {
        Write-Host "added $installDir to your user PATH"
        Write-Host "open a new terminal window before running debun"
    } else {
        Write-Host "$installDir is already in your user PATH"
    }
} finally {
    if (Test-Path $tmpDir) {
        Remove-Item -Path $tmpDir -Recurse -Force
    }
}
