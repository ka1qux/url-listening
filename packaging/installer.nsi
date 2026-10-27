; Instalador Windows do URL Listening (NSIS 3). Gerado por packaging/build.sh.
; Variáveis passadas na linha de comando: VERSION, SRCDIR, ICON, OUTFILE.

Unicode true
!include "MUI2.nsh"

!define APPNAME "URL Listening"
!define LAUNCHER "$INSTDIR\python\pythonw.exe"
!define LAUNCHARGS "-m url_listening.app"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\URLListening"

Name "${APPNAME} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${APPNAME}"
InstallDirRegKey HKLM "${UNINSTKEY}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_FINISHPAGE_RUN "${LAUNCHER}"
!define MUI_FINISHPAGE_RUN_PARAMETERS "${LAUNCHARGS}"
!define MUI_FINISHPAGE_RUN_TEXT "Abrir o ${APPNAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "PortugueseBR"

VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=${LANG_PORTUGUESEBR} "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=${LANG_PORTUGUESEBR} "FileDescription" "Mapeamento de dominios para bloqueio no webfilter"
VIAddVersionKey /LANG=${LANG_PORTUGUESEBR} "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_PORTUGUESEBR} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_PORTUGUESEBR} "CompanyName" "Kaique Oliveira"
VIAddVersionKey /LANG=${LANG_PORTUGUESEBR} "LegalCopyright" "Kaique Oliveira"

Section "Install"
  SetShellVarContext all
  ; Remove arquivos de uma versão anterior antes de copiar a nova.
  RMDir /r "$INSTDIR\python"
  SetOutPath "$INSTDIR"
  File /r "${SRCDIR}\*.*"
  WriteUninstaller "$INSTDIR\Desinstalar.exe"

  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "${LAUNCHER}" "${LAUNCHARGS}" "$INSTDIR\icon.ico"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\Desinstalar.lnk" "$INSTDIR\Desinstalar.exe"
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "${LAUNCHER}" "${LAUNCHARGS}" "$INSTDIR\icon.ico"

  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "Kaique Oliveira"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\Desinstalar.exe"'
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  Delete "$DESKTOP\${APPNAME}.lnk"
  RMDir /r "$SMPROGRAMS\${APPNAME}"
  ; Remove só o que o instalador criou (nunca RMDir /r no $INSTDIR escolhido pelo usuário).
  RMDir /r "$INSTDIR\python"
  Delete "$INSTDIR\url-listening.cmd"
  Delete "$INSTDIR\Abrir URL Listening.cmd"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\Desinstalar.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTKEY}"
SectionEnd
