// Accès au cœur Rust (commandes Tauri). Aucune cryptographie n'est faite en JavaScript.
import { invoke, Channel } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { dirname, join } from '@tauri-apps/api/path';
import { ask, open, save } from '@tauri-apps/plugin-dialog';

export const ENCRYPTED_EXTENSION = '.encrypted';
export const ARCHIVE_MIME = 'application/x-tar';

function channel(onMessage) {
  const ch = new Channel();
  ch.onmessage = (m) => onMessage?.(m);
  return ch;
}

/** @returns {Promise<{path, name, size, isDir, fileCount, inspection: null|{format:string}}>} */
export const inspectFile = (path) => invoke('inspect_file', { path });

export const encryptFile = (input, output, password, deleteOriginal, onProgress) =>
  invoke('encrypt_file', { input, output, password, deleteOriginal, onProgress: channel(onProgress) });

export const encryptSeparately = (inputs, password, deleteOriginals, onProgress) =>
  invoke('encrypt_separately', { inputs, password, deleteOriginals, onProgress: channel(onProgress) });

export const encryptArchive = (inputs, output, password, deleteOriginals, onProgress) =>
  invoke('encrypt_archive', { inputs, output, password, deleteOriginals, onProgress: channel(onProgress) });

export const openEncrypted = (path, password, algorithm) => invoke('open_encrypted', { path, password, algorithm });

export const saveDecrypted = (session, variant, output, onProgress) =>
  invoke('save_decrypted', { session, variant, output, onProgress: channel(onProgress) });

export const extractArchive = (session, parent, onProgress) =>
  invoke('extract_archive', { session, parent, onProgress: channel(onProgress) });

/** @returns {Promise<ArrayBuffer>} contenu déchiffré, en mémoire uniquement */
export const previewContent = (session, variant) => invoke('preview', { session, variant });

export const convertToV3 = (session, variant, output, password) =>
  invoke('convert_to_v3', { session, variant, output, password });

export const decryptMany = (inputs, password, algorithm, outputDir, onProgress) =>
  invoke('decrypt_many', { inputs, password, algorithm, outputDir, onProgress: channel(onProgress) });

export const closeSession = () => invoke('close_session');

export const generatePassphrase = (words = 6) => invoke('generate_passphrase', { words });

export const takePendingRequests = () => invoke('take_pending_requests');

/** Fichiers envoyés par le système (double-clic, clic droit) alors que l'application tourne. */
export const onOpenRequests = (callback) => listen('open-requests', () => callback());

/** Session effacée de la mémoire après inactivité. */
export const onSessionExpired = (callback) => listen('session-expired', () => callback());

/** Glisser-déposer natif : renvoie la fonction de désabonnement (promesse). */
export const onDragDrop = (callback) => getCurrentWebview().onDragDropEvent((e) => callback(e.payload));

export async function pickFiles() {
  const paths = await open({ multiple: true, directory: false, title: 'Choisir des fichiers' });
  if (!paths) return [];
  return Array.isArray(paths) ? paths : [paths];
}

export async function pickFolder(title = 'Choisir un dossier', defaultPath) {
  const path = await open({ directory: true, multiple: false, title, defaultPath });
  return typeof path === 'string' ? path : null;
}

export const pickSavePath = (defaultPath, title) => save({ defaultPath, title });

export const confirmDialog = (message, title = 'Securio') => ask(message, { title, kind: 'warning' });

export const parentOf = (path) => dirname(path);

export async function siblingPath(path, name) {
  return join(await dirname(path), name);
}
