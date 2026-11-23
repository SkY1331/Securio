; Encodage : UTF-8 avec BOM (obligatoire pour que NSIS lise correctement les accents).
; Menu contextuel de l'Explorateur Windows (installation pour l'utilisateur courant).
; Sous Windows 11, ces entrées apparaissent dans « Afficher plus d'options ».
;   - Fichiers et dossiers : « Chiffrer avec Securio »  → securio.exe --encrypt "<chemin>"
;   - Fichiers .encrypted : « Déchiffrer avec Securio » → securio.exe "<chemin>"
; Plusieurs éléments sélectionnés : Windows lance une commande par élément ;
; l'instance unique de Securio les regroupe dans la même fenêtre.

!macro SECURIO_VERB KEY LABEL ARGS
  WriteRegStr HKCU "Software\Classes\${KEY}" "MUIVerb" "${LABEL}"
  WriteRegStr HKCU "Software\Classes\${KEY}" "Icon" '"$INSTDIR\${MAINBINARYNAME}.exe",0'
  WriteRegStr HKCU "Software\Classes\${KEY}\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" ${ARGS}'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro SECURIO_VERB "*\shell\SecurioEncrypt" "Chiffrer avec Securio" '--encrypt "%1"'
  !insertmacro SECURIO_VERB "Directory\shell\SecurioEncrypt" "Chiffrer le dossier avec Securio" '--encrypt "%1"'
  !insertmacro SECURIO_VERB "SystemFileAssociations\.encrypted\shell\SecurioDecrypt" "Déchiffrer avec Securio" '"%1"'
  ; Prévenir l'Explorateur que les associations ont changé
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey HKCU "Software\Classes\*\shell\SecurioEncrypt"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\SecurioEncrypt"
  DeleteRegKey HKCU "Software\Classes\SystemFileAssociations\.encrypted\shell\SecurioDecrypt"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend
