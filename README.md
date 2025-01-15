# WireShark-MVU

Lua plugin for dissecting Milan Vendor Unique information in IEEE1722.1 frames in WireShark

## Manual plugin installation

https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html

### Windows

- Copy all .lua files keeping their folder structure to either one of these directories:

```
C:\Program Files\Wireshark\plugins
```

```
%APPDATA%\Wireshark\plugins
```

### macOS

Is Wireshark is installed as a bundle application, copy the lua files into:

```
<AppName>.app/Contents/Plugins/wireshark
```

Otherwise, copy the lua files to:

```
<InstallationDirectory>/lib/wireshark/plugins
```
