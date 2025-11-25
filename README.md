# Wireshark-MVU

| Plugin           | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| AECP Diagnostics | Additional diagnostics information in IEEE1722.1 AECP frames |
| MVU              | Milan Vendor Unique information in IEEE1722.1 frames         |

## Requirements

The plugins require a minimum version of Wireshark of 4.4.0

# Installing

## Using installer (Windows only)

Execute the installer available in the assets of the Release.

## Manual plugins installation

See online documentation for more details: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html

### On Windows

To manually install on Windows, copy .lua files of the repository from the following source directory to the following target directory:

|                           | MVU                                      | AECP Diagnostics                                      |
| ------------------------- | ---------------------------------------- | ----------------------------------------------------- |
| Copy .lua files from:     | `src/common` and <br/> `src/mvu`         | `src/common` and <br/> `src/aecp-diagnostics`         |
| to: (user installation)   | `%APPDATA%\Wireshark\plugins\mvu`        | `%APPDATA%\Wireshark\plugins\aecp-diagnostics`        |
| to: (global installation) | `C:\Program Files\Wireshark\plugins\mvu` | `C:\Program Files\Wireshark\plugins\aecp-diagnostics` |

### On macOS

To manually install on macOS, copy .lua files of the repository from the following source directory to the following target directory:

|                                                               | MVU                                                           | AECP Diagnostics                                                           |
| ------------------------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Copy .lua files from:                                         | `src/common` and <br/> `src/mvu`                              | `src/common` and <br/> `src/aecp-diagnostics`                              |
| to: (user installation)                                       | `~/.local/lib/wireshark/plugins/mvu`                          | `~/.local/lib/wireshark/plugins/aecp-diagnostics`                          |
| to: (global installation, Wireshark is bundlle application)   | `<AppName>.app/Contents/Plugins/wireshark/mvu`                | `<AppName>.app/Contents/Plugins/wireshark/aecp-diagnostics`                |
| to: (global installation, Wireshark not a bundle application) | `<InstallationDirectory>/lib/wireshark/plugins/wireshark/mvu` | `<InstallationDirectory>/lib/wireshark/plugins/wireshark/aecp-diagnostics` |

### On Atari

_Wireshark is not compatible with this platform._
