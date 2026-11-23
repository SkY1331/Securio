// Lecture des fichiers .encrypted au format v1 (Securio 1.0 → 1.2.1).
//
// ⚠️  Ce module garantit la rétro-compatibilité : il doit reproduire À L'OCTET
// PRÈS le comportement de l'ancien code (voir test/legacy/cryptoUtils.v1.original.js).
// Ne jamais modifier la dérivation de clé ni le découpage ci-dessous.
//
// Structure v1 :
//   [0..64)   en-tête : version uint32 LE (=1) | type uint32 LE | nom (32 octets UTF-8,
//             complété par des 0) | taille des données chiffrées uint32 LE | 20 octets réservés
//   [64..80)  sel PBKDF2 (16 octets)
//   [80..96)  IV AES-CBC (16 octets)
//   [96..)    données AES-CBC (PKCS#7), sans authentification
//   Clé : PBKDF2-HMAC-SHA256, 100 000 itérations, mot de passe encodé "1 octet par
//   unité UTF-16" (charCodeAt & 0xFF), longueur 128/192/256 bits selon l'algorithme
//   choisi — l'algorithme n'est PAS enregistré dans le fichier.

const subtle = () => globalThis.crypto.subtle;

export const V1_HEADER_SIZE = 64;
export const V1_PREFIX_SIZE = V1_HEADER_SIZE + 16 + 16;
export const V1_ITERATIONS = 100000;
export const V1_ALGORITHMS = ['aes-256-cbc', 'aes-192-cbc', 'aes-128-cbc'];

// Encodage historique du mot de passe : chaque unité UTF-16 tronquée à 8 bits.
// (Uint8Array applique un modulo 256, exactement comme l'ancien str2ab.)
export function legacyPasswordBytes(password) {
  const out = new Uint8Array(password.length);
  for (let i = 0; i < password.length; i++) out[i] = password.charCodeAt(i);
  return out;
}

/** Renvoie les infos v1 si `bytes` ressemble à un fichier v1 valide, sinon null. */
export function inspectV1(bytes) {
  if (bytes.length < V1_PREFIX_SIZE + 16) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== 1) return null;
  const dataSize = view.getUint32(40, true);
  if (dataSize === 0 || dataSize % 16 !== 0) return null;
  if (dataSize > bytes.length - V1_PREFIX_SIZE) return null;

  const nameField = bytes.subarray(8, 40);
  const zero = nameField.indexOf(0);
  const nameBytes = zero === -1 ? nameField : nameField.subarray(0, zero);
  let name = new TextDecoder().decode(nameBytes);
  // Le nom a pu être coupé au milieu d'un caractère multi-octets
  const cutMidChar = name.endsWith('�');
  name = name.replace(/�+$/, '').replace(/[\0\s]+$/, '');
  // 32 octets pleins (ou presque, si coupé au milieu d'un caractère) => probablement tronqué
  const possiblyTruncated = zero === -1 || cutMidChar || nameBytes.length >= 29;

  return { format: 'v1', dataSize, headerName: name, possiblyTruncated };
}

async function deriveV1Key(password, salt, algorithm) {
  const length = parseInt(algorithm.split('-')[1], 10);
  const material = await subtle().importKey('raw', legacyPasswordBytes(password), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'PBKDF2', salt, iterations: V1_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-CBC', length },
    false,
    ['decrypt']
  );
}

async function tryDecryptV1(bytes, info, password, algorithm) {
  const salt = bytes.slice(V1_HEADER_SIZE, V1_HEADER_SIZE + 16);
  const iv = bytes.slice(V1_HEADER_SIZE + 16, V1_PREFIX_SIZE);
  const encrypted = bytes.slice(V1_PREFIX_SIZE, V1_PREFIX_SIZE + info.dataSize);
  const key = await deriveV1Key(password, salt, algorithm);
  return new Uint8Array(await subtle().decrypt({ name: 'AES-CBC', iv }, key, encrypted));
}

/**
 * Déchiffre un fichier v1 (l'algorithme n'étant pas stocké dans le fichier).
 *  - algorithm = 'aes-256-cbc' | 'aes-192-cbc' | 'aes-128-cbc' : n'essaie que celui-là
 *    (comportement identique aux anciennes versions) ;
 *  - sinon (« auto ») : essaie AES-256, puis 192, puis 128.
 * Renvoie { plaintext, algorithm }.
 *
 * NB : AES-CBC n'étant pas authentifié, une mauvaise clé peut exceptionnellement
 * (~0,4 % par algorithme essayé) passer le contrôle de remplissage et produire des
 * données incohérentes au lieu d'une erreur. C'est une limite du format v1.
 */
export async function decryptV1(bytes, info, password, preferredAlgorithm) {
  const order = V1_ALGORITHMS.includes(preferredAlgorithm) ? [preferredAlgorithm] : V1_ALGORITHMS;
  for (const algorithm of order) {
    try {
      const plaintext = await tryDecryptV1(bytes, info, password, algorithm);
      return { plaintext, algorithm };
    } catch {
      // mauvais algorithme ou mauvaise clé : on essaie le suivant
    }
  }
  throw new Error(order.length === 1
    ? `Clé incorrecte (ou mauvais algorithme : essayez « Détection automatique »).`
    : 'Clé incorrecte (aucun des algorithmes AES-128/192/256-CBC ne fonctionne).');
}

// ---------------------------------------------------------------------------
// Réparations des fichiers v1 abîmés par l'ancienne interface
// ---------------------------------------------------------------------------
// Jusqu'à la 1.2.1, la zone de dépôt lisait :
//   - les images avec readAsDataURL  => le fichier chiffré contient le TEXTE
//     "data:image/...;base64,...." au lieu de l'image ;
//   - les .txt / text/* avec readAsText puis tronquait chaque caractère à 8 bits
//     => les accents sont devenus du Latin-1, et les caractères au-delà de U+00FF
//     (€, ’, “ ”, –, —, emojis…) ont perdu leur octet de poids fort.
// Ces réparations sont proposées en plus du contenu brut, jamais à sa place
// sans possibilité de revenir au brut.

const DATA_URL_RE = /^data:(image\/[A-Za-z0-9.+-]+)(?:;[^,;]*)*;base64,([A-Za-z0-9+/]*={0,2})$/;

function bytesToLatin1(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return s;
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function repairDataUrlImage(plaintext) {
  // Évite de convertir de gros binaires en chaîne : un data-URL commence par "data:image/"
  if (plaintext.length < 16 || bytesToLatin1(plaintext.subarray(0, 11)) !== 'data:image/') return null;
  const m = DATA_URL_RE.exec(bytesToLatin1(plaintext));
  if (!m) return null;
  try {
    return { content: base64ToBytes(m[2]), type: m[1] };
  } catch {
    return null;
  }
}

function isValidUtf8(bytes) {
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

// Caractères typographiques courants devenus des caractères de contrôle
// (U+20xx & 0xFF). Ces octets n'apparaissent jamais dans un vrai fichier texte.
const TRUNCATED_PUNCTUATION = {
  0x13: '–', // –
  0x14: '—', // —
  0x18: '‘', // ‘
  0x19: '’', // ’
  0x1c: '“', // “
  0x1d: '”', // ”
};

export const TEXT_EXTENSIONS = ['txt', 'text', 'csv', 'tsv', 'md', 'markdown', 'log', 'html', 'htm', 'css', 'js', 'mjs', 'xml', 'ics', 'vcf'];

/**
 * @param {Uint8Array} plaintext
 * @param {boolean} certain  true si l'on sait que le fichier a été lu en texte
 *   (extension .txt) ; sinon on ne répare que si le contenu n'est pas de l'UTF-8 valide.
 */
export function repairLatin1Text(plaintext, certain = false) {
  const hasHigh = plaintext.some((b) => b >= 0x80);
  const hasTruncatedPunct = plaintext.some((b) => b in TRUNCATED_PUNCTUATION);
  if (!hasHigh && !hasTruncatedPunct) return null;
  if (!certain && !hasTruncatedPunct && isValidUtf8(plaintext)) return null;
  let text = '';
  for (const b of plaintext) text += TRUNCATED_PUNCTUATION[b] ?? String.fromCharCode(b);
  return new TextEncoder().encode(text);
}
