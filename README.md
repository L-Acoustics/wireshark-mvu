# Wireshark-MVU

Lua plugin for dissecting Milan Vendor Unique information in IEEE1722.1 frames in Wireshark

## Requirements

The plugin requires a minimum version of Wireshark of 4.4.0

## Manual plugin installation

https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html

### Windows

##### User installation
For user installation, copy all .lua files (from the `src` folder) to the following directory:
```
%APPDATA%\Wireshark\plugins\mvu
```

##### Global installation
For global installation, copy all .lua files (from the `src` folder) to the following directory:
```
C:\Program Files\Wireshark\plugins\mvu
```


_Note: The `mvu` directory is recommended for plugin files organization._

### macOS

##### User installation
For user installation, copy the .lua files into:

```
~/.local/lib/wireshark/plugins/mvu
```

##### Global installation
If Wireshark is installed as a bundle application, copy the .lua files into:

```
<AppName>.app/Contents/Plugins/wireshark/mvu
```

Otherwise, copy the lua files to:

```
<InstallationDirectory>/lib/wireshark/plugins/mvu
```

_Note: The `mvu` directory is recommended for plugin files organization._
