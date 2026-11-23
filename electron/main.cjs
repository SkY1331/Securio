// Processus principal Electron de Securio.
// Le rendu (React) n'a aucun accès à Node : il passe uniquement par l'API
// minimale exposée dans preload.cjs.

const { app, BrowserWindow, ipcMain, dialog, Menu } = require('electron');
const path = require('path');
const fs = require('fs/promises');

const DEV_URL = 'http://localhost:5173';
const isDev = !app.isPackaged && process.argv.includes('--dev');
const MAX_OPEN_SIZE = 2 * 1024 * 1024 * 1024; // 2 Go

let mainWindow = null;
let launchFiles = [];

/** Fichiers .encrypted passés en argument (double-clic, « Ouvrir avec », glisser sur l'exe). */
function encryptedPathsFromArgv(argv) {
  return argv
    .slice(1)
    .filter((a) => !a.startsWith('-') && a.toLowerCase().endsWith('.encrypted'))
    .map((a) => path.resolve(a));
}

async function readForRenderer(filePath) {
  const stat = await fs.stat(filePath);
  if (!stat.isFile()) throw new Error('Ce n’est pas un fichier');
  if (stat.size > MAX_OPEN_SIZE) throw new Error('Fichier trop volumineux');
  const data = await fs.readFile(filePath);
  return { name: path.basename(filePath), data: new Uint8Array(data.buffer, data.byteOffset, data.byteLength) };
}

async function sendOpenFile(filePath) {
  if (!mainWindow) {
    launchFiles.push(filePath);
    return;
  }
  try {
    const file = await readForRenderer(filePath);
    mainWindow.webContents.send('securio:open-file', file);
  } catch (e) {
    dialog.showErrorBox('Securio', `Impossible d'ouvrir ${filePath} : ${e.message}`);
  }
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.focus();
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 760,
    minWidth: 520,
    minHeight: 500,
    title: 'Securio',
    icon: path.join(__dirname, '../dist/icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
    },
  });

  // Aucune nouvelle fenêtre, aucune navigation hors de l'application
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!(isDev && url.startsWith(DEV_URL))) event.preventDefault();
  });

  if (isDev) {
    mainWindow.loadURL(DEV_URL);
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ---------------------------------------------------------------------------
// IPC
// ---------------------------------------------------------------------------

ipcMain.handle('securio:get-launch-files', async () => {
  const files = [];
  for (const p of launchFiles) {
    try {
      files.push(await readForRenderer(p));
    } catch (e) {
      dialog.showErrorBox('Securio', `Impossible d'ouvrir ${p} : ${e.message}`);
    }
  }
  return files;
});

ipcMain.handle('securio:save-file', async (event, suggestedName, data) => {
  if (typeof suggestedName !== 'string' || !(ArrayBuffer.isView(data) || data instanceof ArrayBuffer)) {
    throw new Error('Paramètres invalides');
  }
  const win = BrowserWindow.fromWebContents(event.sender);
  const { canceled, filePath } = await dialog.showSaveDialog(win, {
    defaultPath: path.basename(suggestedName),
  });
  if (canceled || !filePath) return null;
  const bytes = data instanceof ArrayBuffer ? Buffer.from(data) : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  await fs.writeFile(filePath, bytes);
  return filePath;
});

// ---------------------------------------------------------------------------
// Cycle de vie
// ---------------------------------------------------------------------------

if (!app.requestSingleInstanceLock()) {
  // Une instance tourne déjà : elle recevra le fichier via 'second-instance'
  app.quit();
} else {
  launchFiles = encryptedPathsFromArgv(process.argv);

  app.on('second-instance', (_event, argv) => {
    for (const p of encryptedPathsFromArgv(argv)) sendOpenFile(p);
  });

  // macOS : ouverture via le Finder
  app.on('open-file', (event, filePath) => {
    event.preventDefault();
    sendOpenFile(filePath);
  });

  app.whenReady().then(() => {
    if (!isDev) Menu.setApplicationMenu(null);
    createWindow();
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
