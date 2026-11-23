// Pont minimal et sûr entre le rendu et le processus principal.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('securio', {
  /** Fichiers .encrypted reçus au lancement (double-clic, « Ouvrir avec »). */
  getLaunchFiles: () => ipcRenderer.invoke('securio:get-launch-files'),

  /** Ouvre la boîte « Enregistrer sous » ; renvoie le chemin choisi ou null. */
  saveFile: (suggestedName, data) => ipcRenderer.invoke('securio:save-file', suggestedName, data),

  /** Fichier ouvert alors que l'application tourne déjà. Renvoie une fonction de désabonnement. */
  onOpenFile: (callback) => {
    const listener = (_event, file) => callback(file);
    ipcRenderer.on('securio:open-file', listener);
    return () => ipcRenderer.removeListener('securio:open-file', listener);
  },
});
