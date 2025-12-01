# Wireshark-MVU

## Introduction

This repository contains Wireshark dissector plugins for analyzing AVNU Milan protocol traffic. These plugins extend Wireshark's capabilities to decode and display vendor-specific information and diagnostics data in IEEE 1722.1 (AVDECC) network packets.

- **What:** Lua-based Wireshark plugins for Milan protocol analysis
- **Why:** To provide enhanced visibility into Milan Vendor Unique (MVU) messages and AECP diagnostic information that standard Wireshark dissectors don't decode
- **Who:** Network engineers, AV system integrators, and developers working with AVNU Milan/IEEE 1722.1 AVB/TSN networks

Once installed in Wireshark, the plugins add information to packet details, and introduce new display filters.

| Plugin           | Description                                                  | Display filter   |
| ---------------- | ------------------------------------------------------------ | ---------------- |
| AECP Diagnostics | Additional diagnostics information in IEEE1722.1 AECP frames | aecp-diagnostics |
| MVU              | Milan Vendor Unique information in IEEE1722.1 frames         | mvu              |

For instance, packets having errors can be selected using the following display filter: `mvu.has_errors || aecp-diagnostics.has_errors`

#### Disclaimer: Impact on performance

The AECP Diagnostics plugin can significantly slow down the parsing of paquets in Wireshark due to the amount of processing it adds.

## Requirements

The plugins require a minimum version of Wireshark of 4.4.0.

## Installing

### Using installers (🪟 Windows only)

Installers are available in the assets of each Release on GitHub.

1. Download the installer (`.exe` file) from the [Releases page](https://github.com/L-Acoustics/wireshark-mvu/releases)
2. Run the installer with administrator privileges
3. Follow the installation wizard prompts
4. Restart Wireshark if it's currently running

The installer will automatically place the plugin files in the appropriate Wireshark plugins directory. MVU and AECP Diagnostics plugins have distinct installer packages but can be installed concurrently.

**Note:** The installer performs a global installation to `C:\Program Files\Wireshark\plugins\`, making the plugins available to all users on the system.

### Manual plugins installation

See online documentation for more details: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html

#### On 🪟 Windows

To manually install on Windows, copy .lua files of the repository from the following source directory to the following target directory:

|                           | MVU                                      | AECP Diagnostics                                      |
| ------------------------- | ---------------------------------------- | ----------------------------------------------------- |
| Copy .lua files from:     | `src/common` and <br/> `src/mvu`         | `src/common` and <br/> `src/aecp-diagnostics`         |
| to: (user installation)   | `%APPDATA%\Wireshark\plugins\mvu`        | `%APPDATA%\Wireshark\plugins\aecp-diagnostics`        |
| to: (global installation) | `C:\Program Files\Wireshark\plugins\mvu` | `C:\Program Files\Wireshark\plugins\aecp-diagnostics` |

#### On 🍎 macOS/🐧 Linux

To manually install on macOS or Linux, copy .lua files of the repository from the following source directory to the following target directory:

##### User installation

|                       | MVU                                  | AECP Diagnostics                                  |
| --------------------- | ------------------------------------ | ------------------------------------------------- |
| Copy .lua files from: | `src/common` and <br/> `src/mvu`     | `src/common` and <br/> `src/aecp-diagnostics`     |
| to:                   | `~/.local/lib/wireshark/plugins/mvu` | `~/.local/lib/wireshark/plugins/aecp-diagnostics` |

##### Global installation

|                       | MVU                                                           | AECP Diagnostics                                                           |
| --------------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Copy .lua files from: | `src/common` and <br/> `src/mvu`                              | `src/common` and <br/> `src/aecp-diagnostics`                              |
| to:                   | `~/.local/lib/wireshark/plugins/mvu`                          | `~/.local/lib/wireshark/plugins/aecp-diagnostics`                          |
| to:                   | `<InstallationDirectory>/lib/wireshark/plugins/wireshark/mvu` | `<InstallationDirectory>/lib/wireshark/plugins/wireshark/aecp-diagnostics` |

##### Global installation (Wireshark installed as a macOS bundled app)

|                       | MVU                                            | AECP Diagnostics                                            |
| --------------------- | ---------------------------------------------- | ----------------------------------------------------------- |
| Copy .lua files from: | `src/common` and <br/> `src/mvu`               | `src/common` and <br/> `src/aecp-diagnostics`               |
| to:                   | `<AppName>.app/Contents/Plugins/wireshark/mvu` | `<AppName>.app/Contents/Plugins/wireshark/aecp-diagnostics` |

#### On Atari

_Wireshark is not compatible with this platform._

## Known issues

### AECP Diagnostics

#### IN_PROGRESS status code

The IN_PROGRESS status code is not yet handled (The ATDECCEntity is processing the command and will send a second response at a later time with the result of the command).
