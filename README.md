# Wireshark-MVU

Lua plugin for dissecting Milan Vendor Unique information in IEEE1722.1 frames in Wireshark

## Manual plugin installation

https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html

### Windows

Copy all .lua files to either one of the following directories:

```
C:\Program Files\Wireshark\plugins\mvu
```

```
%APPDATA%\Wireshark\plugins\mvu
```

_The `mvu` directory is recommended for plugin files organization._

### macOS

Is Wireshark is installed as a bundle application, copy the .lua files into:

```
<AppName>.app/Contents/Plugins/wireshark/mvu
```

Otherwise, copy the lua files to:

```
<InstallationDirectory>/lib/wireshark/plugins/mvu
```

_The `mvu` directory is recommended for plugin files organization._
