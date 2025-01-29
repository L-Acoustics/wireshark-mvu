# NSIS Installer for Milan Vendor Unique dissector Plugin (Wireshark)
# Author: benjamin.landrot@l-acoustics.com

# --- Includes ---
!include MUI2.nsh
!include nsDialogs.nsh
!include LogicLib.nsh

# --- Constants ---
!define PROGRAM_NAME     "MVU Wireshark Plugin"
!define NAME_SHORT       "MvuWiresharkPlugin"
!define DESC             "A lua-based wireshark plugin for Milan Vendor Unique messages of IEEE 1722.1"
!define COMPANY          ""
!define COPYRIGHT        ""
!define INST_FILE        "mvu-wireshark-plugin-${VERSION}.exe"
!define UNINSTALL_PATH   "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NAME_SHORT}"
!define UNINSTALLER_NAME "uninstall-mvu-wireshark-plugin.exe"

# --- General ---

/*
  Need to check if `RequestExecutionLevel admin` is needed, as we could offer \
  the option to install plugin for user only and write to the %LOCALAPPDATA%
  folder on Windows, which does not require admin priviledges
*/
RequestExecutionLevel admin

Name "${PROGRAM_NAME}"
OutFile "${INST_FILE}"
Unicode true
InstallDir "C:\Program Files\Wireshark\plugins\mvu"
InstallDirRegKey HKEY_LOCAL_MACHINE SOFTWARE\${NAME_SHORT} InstallDir

