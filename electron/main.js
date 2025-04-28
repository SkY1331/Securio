import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: true,
      allowRunningInsecureContent: false
    }
  });

  // En développement, charger l'URL de Vite
  if (process.env.NODE_ENV === 'development') {
    win.loadURL('http://localhost:5173');
    // Ouvrir les outils de développement
    win.webContents.openDevTools();
  } else {
    // En production, charger le fichier index.html
    win.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  // Gérer les arguments de ligne de commande
  ipcMain.handle('get-args', () => {
    return process.argv.slice(1);
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
}); 