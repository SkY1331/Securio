// Format v2 (Securio ≥ 1.3) : chiffrement authentifié.
//
//  Offset Taille  Champ
//  0      7       Magie ASCII "SECURIO"
//  7      1       Version du format (= 2)
//  8      1       KDF   : 1 = PBKDF2-HMAC-SHA256
//  9      4       Itérations KDF (uint32 LE)
//  13     1       Longueur du sel (16)
//  14     1       Chiffrement : 1 = AES-256-GCM
//  15     1       Longueur de l'IV (12)
//  16     n       Sel
//  16+n   m       IV
//  …              Données AES-GCM (dont le tag de 16 octets à la fin)
//
// Tout l'en-tête (de 0 jusqu'à la fin de l'IV) est authentifié (AAD) : la moindre
// modification du fichier fait échouer le déchiffrement.
//
// Contenu chiffré :
//  0  4  Longueur L des métadonnées (uint32 LE)
//  4  L  Métadonnées JSON UTF-8 : { name, type, size }
//  …     Octets du fichier d'origine
//
// Le nom et le type du fichier sont donc chiffrés (ils étaient en clair en v1).
// Les paramètres (itérations, algorithmes) sont enregistrés dans le fichier :
// on peut les durcir dans une version future sans casser la lecture des anciens.

const subtle = () => globalThis.crypto.subtle;

export const MAGIC = 'SECURIO';
export const V2 = 2;
export const KDF_PBKDF2_SHA256 = 1;
export const CIPHER_AES_256_GCM = 1;
// Recommandation OWASP 2023 pour PBKDF2-HMAC-SHA256
export const DEFAULT_ITERATIONS = 600000;
const MAX_ITERATIONS = 10000000; // garde-fou contre un fichier forgé
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

const enc = new TextEncoder();

export function v2PasswordBytes(password) {
  // NFC : un même mot de passe saisi sur macOS/Windows/Linux donne les mêmes octets
  return enc.encode(password.normalize('NFC'));
}

/** Renvoie les paramètres v2 si `bytes` est un fichier v2, sinon null. */
export function inspectV2(bytes) {
  if (bytes.length < 16) return null;
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC.charCodeAt(i)) return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = bytes[7];
  const info = {
    format: 'v2',
    version,
    kdf: bytes[8],
    iterations: view.getUint32(9, true),
    saltLength: bytes[13],
    cipher: bytes[14],
    ivLength: bytes[15],
  };
  info.headerLength = 16 + info.saltLength + info.ivLength;
  return info;
}

function assertSupported(info, bytes) {
  if (info.version !== V2) {
    throw new Error(`Ce fichier utilise le format v${info.version}, créé par une version plus récente de Securio. Mettez l'application à jour.`);
  }
  if (info.kdf !== KDF_PBKDF2_SHA256 || info.cipher !== CIPHER_AES_256_GCM) {
    throw new Error('Algorithme inconnu : ce fichier a été créé par une version plus récente de Securio.');
  }
  if (info.iterations < 1 || info.iterations > MAX_ITERATIONS) throw new Error('En-tête invalide (itérations).');
  if (info.saltLength < 8 || info.ivLength !== IV_LENGTH) throw new Error('En-tête invalide.');
  if (bytes.length < info.headerLength + TAG_LENGTH + 4) throw new Error('Fichier tronqué.');
}

async function deriveKey(password, salt, iterations, usage) {
  const material = await subtle().importKey('raw', v2PasswordBytes(password), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage]
  );
}

export async function encryptV2(data, password, meta, { iterations = DEFAULT_ITERATIONS } = {}) {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const header = new Uint8Array(16 + SALT_LENGTH + IV_LENGTH);
  const view = new DataView(header.buffer);
  header.set(enc.encode(MAGIC), 0);
  header[7] = V2;
  header[8] = KDF_PBKDF2_SHA256;
  view.setUint32(9, iterations, true);
  header[13] = SALT_LENGTH;
  header[14] = CIPHER_AES_256_GCM;
  header[15] = IV_LENGTH;
  header.set(salt, 16);
  header.set(iv, 16 + SALT_LENGTH);

  const metaBytes = enc.encode(JSON.stringify({ name: meta.name, type: meta.type, size: data.length }));
  const plain = new Uint8Array(4 + metaBytes.length + data.length);
  new DataView(plain.buffer).setUint32(0, metaBytes.length, true);
  plain.set(metaBytes, 4);
  plain.set(data, 4 + metaBytes.length);

  const key = await deriveKey(password, salt, iterations, 'encrypt');
  const ciphertext = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, key, plain)
  );
  plain.fill(0);

  const out = new Uint8Array(header.length + ciphertext.length);
  out.set(header, 0);
  out.set(ciphertext, header.length);
  return out;
}

export async function decryptV2(bytes, info, password) {
  assertSupported(info, bytes);
  const header = bytes.slice(0, info.headerLength);
  const salt = header.slice(16, 16 + info.saltLength);
  const iv = header.slice(16 + info.saltLength, info.headerLength);
  const key = await deriveKey(password, salt, info.iterations, 'decrypt');

  let plain;
  try {
    plain = new Uint8Array(
      await subtle().decrypt(
        { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 },
        key,
        bytes.subarray(info.headerLength)
      )
    );
  } catch {
    throw new Error('Clé incorrecte ou fichier modifié/corrompu.');
  }

  const metaLength = new DataView(plain.buffer).getUint32(0, true);
  if (4 + metaLength > plain.length) throw new Error('Métadonnées invalides.');
  const meta = JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + metaLength)));
  const content = plain.slice(4 + metaLength);
  plain.fill(0);
  return { content, name: meta.name, type: meta.type || 'application/octet-stream' };
}
