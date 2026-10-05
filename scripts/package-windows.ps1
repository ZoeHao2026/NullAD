param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "../dist")
)
$ErrorActionPreference = "Stop"
$repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$destination = [System.IO.Path]::GetFullPath($OutputDirectory)
$configuration = Get-Content -LiteralPath (Join-Path $repository "crates/nullad-desktop/tauri.conf.json") -Raw | ConvertFrom-Json
$productName = [string]$configuration.productName
$version = [string]$configuration.version
foreach ($value in @($productName, $version)) {
    if ([string]::IsNullOrWhiteSpace($value) -or $value.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        throw "Tauri productName/version must be present and valid in a Windows filename."
    }
}
$installerName = "${productName}_${version}_x64-setup.exe"
$installer = Join-Path $repository "target/release/bundle/nsis/$installerName"
$kinds = @("desktop", "cli")
$extensionFiles = @("manifest.json", "background.js", "domain-rules.js", "policy.js", "detector.js", "content.js", "i18n.js", "popup.html", "popup.js", "popup.css", "options.html", "options.js", "README.md", "THIRD_PARTY_NOTICES.md")
$outputNames = @("nullad-desktop-windows-x64.zip", "nullad-cli-windows-x64.zip", "nullad-browser-extension.zip", $installerName, "SHA256SUMS.txt")

# Validate every input and output before creating a staging or delivery directory.
$issues = @()
$requiredFiles = @(
    $installer,
    (Join-Path $repository "target/release/nullad-desktop.exe"),
    (Join-Path $repository "target/release/nullad-cli.exe"),
    (Join-Path $repository "lists/nullad-base.txt"),
    (Join-Path $repository "lists/nullad-hosts.txt"),
    (Join-Path $repository "lists/THIRD_PARTY_NOTICES.md"),
    (Join-Path $repository "rules/README.md"),
    (Join-Path $repository "rules/sources.lock.json"),
    (Join-Path $repository "rules/metadata.json"),
    (Join-Path $repository "scripts/update-bundled-rules.py"),
    (Join-Path $repository "docs/windows-validation.md"),
    (Join-Path $repository "docs/performance.md"),
    (Join-Path $repository "README.md"),
    (Join-Path $repository "README.zh-CN.md"),
    (Join-Path $repository "LICENSE")
)
$requiredFiles += $extensionFiles | ForEach-Object { Join-Path $repository "extension/$_" }
foreach ($path in $requiredFiles) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
        $issues += "Missing required package input: $path"
    } elseif ((Get-Item -LiteralPath $path).Length -eq 0) {
        $issues += "Required package input is empty: $path"
    }
}
foreach ($directory in @("lists", "docs", "rules")) {
    $path = Join-Path $repository $directory
    if (!(Test-Path -LiteralPath $path -PathType Container)) {
        $issues += "Missing required package directory: $path"
    }
}
if ((Test-Path -LiteralPath $destination) -and !(Test-Path -LiteralPath $destination -PathType Container)) {
    $issues += "Output path is not a directory: $destination"
}
foreach ($name in $outputNames) {
    $path = Join-Path $destination $name
    if (Test-Path -LiteralPath $path) { $issues += "Output already exists: $path. Choose a fresh output directory." }
}
if ($issues.Count -gt 0) { throw ($issues -join [Environment]::NewLine) }

$targetDirectory = [System.IO.Path]::GetFullPath((Join-Path $repository "target"))
$stage = [System.IO.Path]::GetFullPath((Join-Path $targetDirectory ("package-staging-" + [System.Guid]::NewGuid().ToString("N"))))
if (!$stage.StartsWith($targetDirectory + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Package staging must remain inside the repository target directory."
}
$ready = Join-Path $stage "artifacts"
$published = [System.Collections.Generic.List[string]]::new()
try {
    New-Item -ItemType Directory -Path $ready -Force | Out-Null
    foreach ($kind in $kinds) {
        $package = Join-Path $stage $kind
        New-Item -ItemType Directory -Path $package | Out-Null
        Copy-Item -LiteralPath (Join-Path $repository "target/release/nullad-$kind.exe") -Destination $package
        Copy-Item -LiteralPath (Join-Path $repository "lists") -Destination $package -Recurse
        Copy-Item -LiteralPath (Join-Path $repository "docs") -Destination $package -Recurse
        Copy-Item -LiteralPath (Join-Path $repository "rules") -Destination $package -Recurse
        $packageScripts = Join-Path $package "scripts"
        New-Item -ItemType Directory -Path $packageScripts | Out-Null
        Copy-Item -LiteralPath (Join-Path $repository "scripts/update-bundled-rules.py") -Destination $packageScripts
        $packageExtension = Join-Path $package "extension"
        New-Item -ItemType Directory -Path $packageExtension | Out-Null
        foreach ($name in $extensionFiles) {
            Copy-Item -LiteralPath (Join-Path $repository "extension/$name") -Destination $packageExtension
        }
        Copy-Item -LiteralPath (Join-Path $repository "LICENSE") -Destination $packageExtension
        foreach ($name in @("README.md", "README.zh-CN.md", "LICENSE")) {
            Copy-Item -LiteralPath (Join-Path $repository $name) -Destination $package
        }
        Compress-Archive -Path (Join-Path $package "*") -DestinationPath (Join-Path $ready "nullad-$kind-windows-x64.zip") -CompressionLevel Optimal
    }
    $extension = Join-Path $stage "extension"
    New-Item -ItemType Directory -Path $extension | Out-Null
    foreach ($name in $extensionFiles) {
        Copy-Item -LiteralPath (Join-Path $repository "extension/$name") -Destination $extension
    }
    Copy-Item -LiteralPath (Join-Path $repository "LICENSE") -Destination $extension
    Compress-Archive -Path (Join-Path $extension "*") -DestinationPath (Join-Path $ready "nullad-browser-extension.zip") -CompressionLevel Optimal
    Copy-Item -LiteralPath $installer -Destination (Join-Path $ready $installerName)
    $checksums = foreach ($name in $outputNames | Where-Object { $_ -ne "SHA256SUMS.txt" } | Sort-Object) {
        $hash = Get-FileHash -LiteralPath (Join-Path $ready $name) -Algorithm SHA256
        "$($hash.Hash.ToLower())  $name"
    }
    $checksums | Set-Content -LiteralPath (Join-Path $ready "SHA256SUMS.txt") -Encoding ascii

    # Publish only after every ZIP, the exact installer and checksums are complete.
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    foreach ($name in $outputNames) {
        $path = Join-Path $destination $name
        Move-Item -LiteralPath (Join-Path $ready $name) -Destination $path
        $published.Add($path)
    }
} catch {
    foreach ($path in $published) {
        try { Remove-Item -LiteralPath $path -Force } catch { Write-Warning "Could not remove incomplete package output: $path" }
    }
    throw
} finally {
    if (Test-Path -LiteralPath $stage) {
        try { Remove-Item -LiteralPath $stage -Recurse -Force } catch { Write-Warning "Could not remove package staging: $stage" }
    }
}
Write-Output "Packages created in $destination"
