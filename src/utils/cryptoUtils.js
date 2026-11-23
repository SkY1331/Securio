// Point d'entrée cryptographique de Securio.
//
//  - Chiffrement : toujours au format v2 (AES-256-GCM authentifié).
//  - Déchiffrement : formats v2 ET v1 (fichiers créés par Securio 1.0 → 1.2.1).
//
// Voir formatV2.js et legacyV1.js pour le détail des formats.

import { inspectV2, encryptV2, decryptV2 } from './formatV2.js';
import {
  inspectV1,
  decryptV1,
  repairDataUrlImage,
  repairLatin1Text,
  TEXT_EXTENSIONS,
} from './legacyV1.js';

export const ENCRYPTED_EXTENSION = '.encrypted';
export { V1_ALGORITHMS } from './legacyV1.js';

export function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new Error('Type de données non supporté');
}

/** Rend un nom de fichier sûr pour l'enregistrement (Windows/macOS/Linux). */
export function sanitizeFileName(name, fallback = 'fichier') {
  const clean = String(name ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_')
    .replace(/^[\s.]+|[\s.]+$/g, '')
    .slice(0, 200);
  return clean || fallback;
}

/** Nom d'origine déduit du nom du fichier chiffré ("a.pdf.encrypted", "a.pdf (1).encrypted"). */
export function nameFromEncryptedName(outerName) {
  if (!outerName) return '';
  const base = outerName.split(/[\\/]/).pop();
  if (!base.toLowerCase().endsWith(ENCRYPTED_EXTENSION)) return '';
  return base.slice(0, -ENCRYPTED_EXTENSION.length).replace(/ \(\d+\)$/, '');
}

/**
 * Identifie un fichier Securio.
 * @returns {{format:'v1'|'v2', ...}|null}
 */
export function inspectFile(data) {
  const bytes = toBytes(data);
  return inspectV2(bytes) || inspectV1(bytes);
}

export function isEncryptedFile(data) {
  return inspectFile(data) !== null;
}

/**
 * Chiffre un fichier au format v2.
 * @param {ArrayBuffer|Uint8Array} data
 * @param {string} password
 * @param {{name?:string, type?:string}} meta
 * @returns {Promise<Uint8Array>}
 */
export async function encryptFile(data, password, meta = {}, options) {
  if (!password) throw new Error('La clé secrète ne peut pas être vide');
  const bytes = toBytes(data);
  return encryptV2(bytes, password, {
    name: meta.name || 'fichier',
    type: meta.type || 'application/octet-stream',
  }, options);
}

/**
 * Déchiffre un fichier Securio (v2 ou v1).
 * @param {ArrayBuffer|Uint8Array} data
 * @param {string} password
 * @param {{algorithm?:string, outerName?:string}} options
 *   algorithm : pour les fichiers v1, algorithme imposé ('aes-256-cbc'…) ou absent/'auto'
 *   outerName : nom du fichier .encrypted (sert à retrouver un nom v1 tronqué)
 * @returns {Promise<{content:Uint8Array, name:string, type:string, format:string,
 *   algorithm:string, warnings:string[], alternatives:Array<{label:string, content:Uint8Array, name:string, type:string}>}>}
 */
export async function decryptFile(data, password, options = {}) {
  if (!password) throw new Error('La clé secrète ne peut pas être vide');
  const bytes = toBytes(data);
  const info = inspectFile(bytes);
  if (!info) throw new Error("Ce fichier n'est pas un fichier chiffré par Securio.");

  if (info.format === 'v2') {
    const r = await decryptV2(bytes, info, password);
    return {
      ...r,
      name: sanitizeFileName(r.name),
      format: 'v2',
      algorithm: 'aes-256-gcm',
      warnings: [],
      alternatives: [],
    };
  }

  // ---- Format v1 (rétro-compatibilité) ----
  const { plaintext, algorithm } = await decryptV1(bytes, info, password, options.algorithm);
  const warnings = [];
  const alternatives = [];


  let name = info.headerName;
  const outer = nameFromEncryptedName(options.outerName);
  if (info.possiblyTruncated) {
    if (outer && name && outer.startsWith(name)) {
      name = outer;
    } else {
      warnings.push(`Le nom d'origine a pu être tronqué à 32 octets par l'ancienne version (« ${name} »). Vérifiez l'extension avant d'ouvrir le fichier.`);
    }
  }
  name = sanitizeFileName(name || outer);

  let content = plaintext;
  let type = 'application/octet-stream';
  const raw = { label: 'Contenu brut (tel que stocké)', content: plaintext, name, type };

  const image = repairDataUrlImage(plaintext);
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (image) {
    content = image.content;
    type = image.type;
    warnings.push('Image chiffrée par une ancienne version (stockée en texte « data: ») : elle a été reconvertie automatiquement en image.');
    alternatives.push(raw);
  } else if (TEXT_EXTENSIONS.includes(ext)) {
    const certain = ext === 'txt';
    const repaired = repairLatin1Text(plaintext, certain);
    if (repaired) {
      const fixed = { label: 'Version texte réparée (UTF-8)', content: repaired, name, type: 'text/plain' };
      warnings.push(
        "Fichier texte chiffré par une ancienne version : les caractères accentués avaient été stockés en Latin-1. " +
          (certain ? 'Ils ont été reconvertis en UTF-8. ' : 'Une version réparée est proposée. ') +
          "Les caractères hors Latin-1 (€, emojis…) ont pu être altérés définitivement à l'époque ; € apparaît souvent comme ¬."
      );
      if (certain) {
        content = repaired;
        type = 'text/plain';
        alternatives.push(raw);
      } else {
        alternatives.push(fixed);
      }
    }
  }

  return { content, name, type, format: 'v1', algorithm, warnings, alternatives };
}
