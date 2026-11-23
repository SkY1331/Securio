// Accès au cœur Rust (commandes Tauri). Aucune cryptographie n'est faite en JavaScript.
import { invoke, Channel } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { dirname, join } from '@tauri-apps/api/path';
import { open, save } from '@tauri-apps/plugin-dialog';

export const ENCRYPTED_EXTENSION = '.encrypted';

/** @returns {Promise<{path:string, name:string, size:number, inspection:null|{format:string}}>} */
export const inspectFile = (path) => invoke('inspect_file', { path });

function progressChannel(onProgress) {
  const channel = new Channel();
  channel.onmessage = (n) => onProgress?.(n);
  return channel;
}

export const encryptFile = (input, output, password, onProgress) =>
  invoke('encrypt_file', { input, output, password, onProgress: progressChannel(onProgress) });

export const openEncrypted = (path, password, algorithm) =>
  invoke('open_encrypted', { path, password, algorithm });

export const saveDecrypted = (session, variant, output, onProgress) =>
  invoke('save_decrypted', { session, variant, output, onProgress: progressChannel(onProgress) });

export const closeSession = () => invoke('close_session');

export const launchFiles = () => invoke('launch_files');

/** Fichier ouvert (double-clic) alors que l'application tourne déjà. */
export const onOpenFile = (callback) => listen('open-file', (e) => callback(e.payload));

/** Glisser-déposer natif : renvoie la fonction de désabonnement (promesse). */
export const onDragDrop = (callback) => getCurrentWebview().onDragDropEvent((e) => callback(e.payload));

export async function pickFile() {
  const path = await open({ multiple: false, directory: false, title: 'Choisir un fichier' });
  return typeof path === 'string' ? path : null;
}

export async function pickSavePath(defaultPath, title) {
  return save({ defaultPath, title });
}

export async function siblingPath(path, name) {
  return join(await dirname(path), name);
}
