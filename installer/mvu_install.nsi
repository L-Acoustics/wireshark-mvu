# NSIS Installer for Milan Vendor Unique dissector Plugin (Wireshark)
# Author: benjamin.landrot@l-acoustics.com

# --- Includes ---
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "version.nsh"
!include "VersionCompare.nsh"

# --- Constants ---
!define PROGRAM_NAME          "MVU Wireshark Plugin"
!define NAME_SHORT            "MVU_Wireshark_Plugin"
!define DESC                  "A lua-based plugin for Wireshark to help analyzing Milan Vendor Unique messages of IEEE 1722.1"
!define COMPANY               "L-Acoustics"
!define COPYRIGHT             "(c) L-Acoustics"
!define INST_FILE             "mvu-wireshark-plugin-${VERSION}.exe"
!define UNINSTALL_PATH        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NAME_SHORT}"
!define UNINSTALLER_NAME      "uninstall-mvu-wireshark-plugin.exe"
!define WS_UNINSTALL_PATH     "Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark"
!define WS_MINIMUM_VERSION_REQUIRED "4.4.0"

# --- General ---
RequestExecutionLevel user
Name "${PROGRAM_NAME}"
OutFile "${INST_FILE}"
Unicode true
# Installing files to Wireshark user plugins folder. This makes it survive Wireshark reinstallations
# and avoids the need of requesting admin execution level for installing
InstallDir "$APPDATA\Wireshark\plugins\mvu"
InstallDirRegKey HKEY_CURRENT_USER SOFTWARE\${NAME_SHORT} InstallDir

# --- Version ---
VIProductVersion "${VERSION}"
VIAddVersionKey "ProductName" "${NAME}"
VIAddVersionKey "CompanyName" "${COMPANY}"
VIAddVersionKey "LegalTrademarks" "${COPYRIGHT}"
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"
VIAddVersionKey "FileDescription" "${DESC}"
VIAddVersionKey "FileVersion" "${VERSION}"

# --- UI Appearance ---
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_HEADERIMAGE
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "MVU Wireshark Plugin"
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PROGRAM_NAME}.$\r$\n$\r$\n${PROGRAM_NAME} supports Wireshark 4.4.0 or newer, so make sure to install a supported version of Wireshark to be able to use this plugin. $\r$\n$\r$\nClick 'Next' to continue."

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

; --- Variables ---
VAR INSTALLED_VERSION
VAR WS_INSTALLED_VERSION

# --- .onInit / un.onInit functions ---
Function .onInit

	# --- Control installed version of Wireshark ---
	
	# Get the installed version of Wiresharkj (x64) if it exists
	ReadRegStr $WS_INSTALLED_VERSION HKEY_LOCAL_MACHINE "${WS_UNINSTALL_PATH}" "DisplayVersion"

	# If an installed version of Wireshark x64 was found
	${If} $WS_INSTALLED_VERSION != ""

		# Compare installed and minimum required versions of Wireshark
		${VersionCompare} $WS_INSTALLED_VERSION ${WS_MINIMUM_VERSION_REQUIRED} $0

		# If installed version older than the minimum required
		${If} $0 == 2

			# Inform user and ask approval for continuing install with unsupported Wireshark
			MessageBox MB_YESNO|MB_ICONEXCLAMATION "And installation of Wireshark $WS_INSTALLED_VERSION was detected on this system. This plugin is compatible with Wireshark 4.4.0 or newer. You need to update your version of Wireshark for this plugin to work. Do you wish to install the plugin anyway?" IDYES ContinueWithUnsupportedWireshark
				# If NO, stop
				Abort
			
			# If YES, continue installing
			ContinueWithUnsupportedWireshark:
								
		${EndIf}
		
	${Else}

		# Inform the user Wireshark is not installed and ask to continue
		MessageBox MB_YESNO|MB_ICONEXCLAMATION "Wireshark x64 is not installed on this computer. This plugin is compatible with Wireshark 4.4.0 or newer. Do you wish to continue installing this plugin anyway?" IDYES ContinueWithoutWiresharkInstalled
			# If NO, stop
			Abort

		# If YES, continue installing
		ContinueWithoutWiresharkInstalled:

	${EndIf}

	# --- Control previsouly installed version of this program ---

	# Get the existing installed version if it exists
	ReadRegStr $INSTALLED_VERSION HKEY_CURRENT_USER "${UNINSTALL_PATH}" "DisplayVersion"

	# If an installed version was found
	${If} $INSTALLED_VERSION != ""

		# Compare installed version with the one embedded in this installer
		${VersionCompare} $INSTALLED_VERSION ${VERSION} $0

		# If versions are equel
		${If} $0 == 0
			# Inform user
			MessageBox MB_OK|MB_ICONINFORMATION "The installed version (${VERSION}) of ${PROGRAM_NAME} is already up to date."
			# Stop
			Abort

		# If installed version is older
		${ElseIf} $0 == 2
			# Ask if the user wants to uninstall first
			MessageBox MB_YESNO|MB_ICONQUESTION "An older version ($INSTALLED_VERSION) of ${PROGRAM_NAME} was found. Would you like to uninstall it first?" IDYES Cleanup
				# If refused, stop
				Abort
			
			# If accepted
			Cleanup:
				# Read uninstaller path
				ReadRegStr $0 HKEY_CURRENT_USER "${UNINSTALL_PATH}" "UninstallString"
				# Execute uninstaller
				ExecWait '$0 /S'

		# If installed version is newer
		${ElseIf} $0 == 1
			# Ask if the user wants to downgrade
			MessageBox MB_YESNO|MB_ICONQUESTION "A newer version ($INSTALLED_VERSION) of ${PROGRAM_NAME} is already installed. Do you want to continue (existing version will be uninstalled)?" IDYES Continue
				# If refused, stop
				Abort

			# If accepted
			Continue:
				# Read uninstaller path
				ReadRegStr $0 HKEY_CURRENT_USER "${UNINSTALL_PATH}" "UninstallString"
				# Execute uninstaller
				ExecWait '$0 /S'
								
		${EndIf}

	${EndIf}

FunctionEnd

# --- Sections ---
Section "MVU Plugin" SEC_MVU_PLUGIN

	# Write the installation path into the registry
	WriteRegStr HKEY_CURRENT_USER SOFTWARE\${NAME_SHORT} InstallDir "$INSTDIR"
	WriteRegStr HKEY_CURRENT_USER "${UNINSTALL_PATH}" "DisplayName" "${PROGRAM_NAME}"
	WriteRegStr HKEY_CURRENT_USER "${UNINSTALL_PATH}" "DisplayVersion" "${VERSION}"
	WriteRegStr HKEY_CURRENT_USER "${UNINSTALL_PATH}" "InstallLocation" "$INSTDIR"

	# Write the uninstall keys for Windows
	WriteRegDWORD HKEY_CURRENT_USER "${UNINSTALL_PATH}" "NoModify" 1
	WriteRegDWORD HKEY_CURRENT_USER "${UNINSTALL_PATH}" "NoRepair" 1
	WriteRegStr HKEY_CURRENT_USER "${UNINSTALL_PATH}" "UninstallString" '"$INSTDIR\${UNINSTALLER_NAME}"'
	WriteRegStr HKEY_CURRENT_USER "${UNINSTALL_PATH}" "QuietUninstallString" '"$INSTDIR\${UNINSTALLER_NAME}" /S'

	# Write program files
	SetOutPath "$INSTDIR"
	WriteUninstaller "$INSTDIR\${UNINSTALLER_NAME}"
	FILE "..\src\*.lua"

SectionEnd

Section "Uninstall"

	# --- Remove Registry Keys ---
	DeleteRegKey HKEY_CURRENT_USER SOFTWARE\${NAME_SHORT}
	DeleteRegKey HKEY_CURRENT_USER "${UNINSTALL_PATH}"

	# --- Remove Files ---
	RMDir /r "$INSTDIR"

SectionEnd

