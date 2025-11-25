# Wireshark-MVU - NSIS Windows Installer

NSIS is used to generate an installer for Windows.

## How to compile the installer

NSIS must be installed in the system.

Execute one of the following command:

```
makensis mvu_install.nsi
```

```
makensis aecp-diagnostics_install.nsi
```

Example output of the makenins operation:

    Processing config: C:\Program Files (x86)\NSIS\nsisconf.nsh
    Processing script file: ".\mvu_install.nsi" (ACP)

    Processed 1 file, writing output (x86-unicode):
    Done Adding Additional Store
    Successfully signed: C:\Users\USERN~1.LAN\AppData\Local\Temp\nstC85D.tmp

    Output: "D:\wireshark-mvu\installer\build\mvu-wireshark-plugin-1.2.1.0.exe"
    Install: 6 pages (384 bytes), 1 section (2072 bytes), 506 instructions (14168 bytes), 247 strings (46414 bytes), 1 language table (346 bytes).
    Uninstall: 4 pages (320 bytes), 1 section (2072 bytes), 350 instructions (9800 bytes), 167 strings (5120 bytes), 1 language table (290 bytes).
    Datablock optimizer saved 1888 bytes (~1.1%).

    Using zlib compression.

    EXE header size:               55808 / 39936 bytes
    Install code:                  13238 / 63848 bytes
    Install data:                  46213 / 172867 bytes
    Uninstall code+data:           61073 / 83336 bytes
    CRC (0xA95FC692):                  4 / 4 bytes

    Total size:                   176336 / 359991 bytes (48.9%)
    Done Adding Additional Store
    Successfully signed: mvu-wireshark-plugin-1.2.1.0.exe
