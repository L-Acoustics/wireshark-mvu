# Move to installer folder
Set-Location -Path (Join-Path $PSScriptRoot "..\installer")

# Build both installers (x64 and x86)
& makensis mvu_install.nsi
& makensis aecp-diagnostics_install.nsi