# NSIS Installer for Milan Vendor Unique dissector Plugin (Wireshark)
# Author: benjamin.landrot@l-acoustics.com

# --- Includes ---
!include MUI2.nsh
!include nsDialogs.nsh
!include LogicLib.nsh
!include version.nsh

# --- Constants ---
!define PROGRAM_NAME     "MVU Wireshark Plugin"
!define NAME_SHORT       "MvuWiresharkPlugin"
!define DESC             "A lua-based wireshark plugin for Milan Vendor Unique messages of IEEE 1722.1"
!define COMPANY          "L-Acoustics"
!define COPYRIGHT        "(c) L-Acoustics"
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

# Version
VIProductVersion "${VERSION}"
VIAddVersionKey "ProductName" "${NAME}"
VIAddVersionKey "CompanyName" "${COMPANY}"
VIAddVersionKey "LegalTrademarks" "${COPYRIGHT}"
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"
VIAddVersionKey "FileDescription" "${DESC}"
VIAddVersionKey "FileVersion" "${VERSION}"

# --- UI Appearance ---
!define MUI_FINISHPAGE_NOAUTOCLOSE
#!define MUI_ICON "assets\icon\icon48.ico"
#!define MUI_UNICON "assets\icon\icon48.ico"
!define MUI_HEADERIMAGE
#!define MUI_HEADERIMAGE_BITMAP "assets\header.bmp"
#!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\welcome.bmp"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "MVU Wireshark Plugin"
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PROGRAM_NAME}.$\r$\n$\r$\nBefore starting the installation, make sure ${PROGRAM_NAME} is not running.$\r$\n$\r$\nClick 'Next' to continue."

# --- Installer Pages ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "assets\gpl-2.0.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

# --- Uninstaller Pages ---
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH
!insertmacro MUI_LANGUAGE "English"


Section "MVU Plugin" SEC_MVU

  # Write the installation path into the registry
	WriteRegStr HKEY_LOCAL_MACHINE SOFTWARE\${NAME_SHORT} InstallDir "$INSTDIR"
	WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "DisplayName" "${PROGRAM_NAME}"
	WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "DisplayVersion" "${VERSION}"
	WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "InstallLocation" "$INSTDIR"

  # Write the uninstall keys for Windows
	WriteRegDWORD HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "NoModify" 1
	WriteRegDWORD HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "NoRepair" 1
	WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "UninstallString" '"$INSTDIR\${UNINSTALLER_NAME}"'
	WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "QuietUninstallString" '"$INSTDIR\${UNINSTALLER_NAME}" /S'
	
  # Write program files
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\${UNINSTALLER_NAME}"
  FILE "..\src\*.lua"
  ; FILE "..\src\ieee17221_fields.lua"
  ; FILE "..\src\ieee17221_specs.lua"
  ; FILE "..\src\ieee8023_specs.lua"
  ; FILE "..\src\mvu.lua"
  ; FILE "..\src\mvu_control.lua"
  ; FILE "..\src\mvu_conversations.lua"
  ; FILE "..\src\mvu_feature_clock_reference_info.lua"
  ; FILE "..\src\mvu_feature_milan_info.lua"
  ; FILE "..\src\mvu_feature_system_unique_id.lua"
  ; FILE "..\src\mvu_fields.lua"
  ; FILE "..\src\mvu_headers.lua"
  ; FILE "..\src\mvu_helpers.lua"
  ; FILE "..\src\mvu_plugin_info.lua"
  ; FILE "..\src\mvu_proto.lua"
  ; FILE "..\src\mvu_specs.lua"

SectionEnd

Section "Uninstall"

	# --- Remove Registry Keys ---
	DeleteRegKey HKEY_LOCAL_MACHINE SOFTWARE\${NAME_SHORT}
	DeleteRegKey HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}"

	# --- Remove Files ---
	RMDir /r "$INSTDIR"

SectionEnd

