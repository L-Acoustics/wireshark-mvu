# Function to write colored output to the console
function Write-ColorOutput($ForegroundColor)
{
    # save the current color
    $fc = $host.UI.RawUI.ForegroundColor

    # set the new color
    $host.UI.RawUI.ForegroundColor = $ForegroundColor

    # output
    if ($args) {
        Write-Output $args
    }
    else {
        $input | Write-Output
    }

    # restore the original color
    $host.UI.RawUI.ForegroundColor = $fc
}

# Function to copy lua files from source directories to plugin destination
function Install-UserWiresharkPlugin {
    param(
        [string]$PluginName,
        [string[]]$SourceDirs
    )
    
    $pluginDst = Join-Path $env:APPDATA "Wireshark/plugins/$PluginName"
    
    # Create destination directory if it doesn't exist
    if (-not (Test-Path $pluginDst)) {
        Write-ColorOutput White "Creating directory $pluginDst"
        New-Item -ItemType Directory -Path $pluginDst -Force | Out-Null
    }
    
    # Clean existing Lua files
    Write-ColorOutput White "Cleaning existing Lua files in $pluginDst"
    if (Test-Path $pluginDst) {
        Get-ChildItem -Path $pluginDst -Recurse | Remove-Item -Recurse -Force
    }
    
    # Copy lua files from each source directory
    foreach ($srcDir in $SourceDirs) {
        $fullSrcPath = Join-Path $PSScriptRoot "..\$srcDir"
        
        if (-not (Test-Path $fullSrcPath)) {
            Write-Warning "Source directory not found: $fullSrcPath (skipping)"
            continue
        }
        
        Write-ColorOutput White "Copying Lua files from $srcDir to $pluginDst"
        Get-ChildItem -Path $fullSrcPath -Filter '*.lua' -Recurse | ForEach-Object {
            $destination = Join-Path $pluginDst $_.Name
            Copy-Item -Path $_.FullName -Destination $destination -Force
            Write-ColorOutput DarkGray "Copied: $($_.FullName) -> $destination"
        }
    }
    
    Write-ColorOutput Green "Deployment of $PluginName completed"
}

# Install MVU plugin
Install-UserWiresharkPlugin -PluginName "mvu" -SourceDirs @("src/common", "src/mvu")

# Install AECP Diagnostics plugin
# Install-UserWiresharkPlugin -PluginName "aecp-diagnostics" -SourceDirs @("src/common", "src/aecp-diagnostics")
