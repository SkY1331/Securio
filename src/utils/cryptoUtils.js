// Utilisation de l'API Web Crypto
const crypto = window.crypto;

// Fonction pour convertir une chaîne en tableau d'octets
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;
}

// Fonction pour convertir un tableau d'octets en chaîne
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

// Fonction pour convertir un tableau d'octets en chaîne hexadécimale
function buf2hex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// Fonction pour convertir une chaîne hexadécimale en tableau d'octets
function hex2buf(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return arr;
}

// Fonction pour dériver une clé à partir d'une chaîne
async function deriveKey(password, salt, algorithm) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    str2ab(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: str2ab(salt || 'salt'),
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    {
      name: 'AES-CBC',
      length: parseInt(algorithm.split('-')[1], 10),
    },
    false,
    ['encrypt', 'decrypt']
  );
}

// Constantes pour le format de fichier
const FILE_FORMAT_VERSION = 1;
const HEADER_SIZE = 64; // Taille fixe de l'en-tête en octets

// Structure de l'en-tête :
// - 4 octets : version (uint32)
// - 4 octets : type de fichier (uint32, index dans la liste des types)
// - 32 octets : nom du fichier (utf8, padding avec des zéros)
// - 4 octets : taille des données (uint32)
// - 20 octets : réservé pour extensions futures

const FILE_TYPES = {
  'application/octet-stream': 0
};

const FILE_TYPES_REVERSE = Object.fromEntries(
  Object.entries(FILE_TYPES).map(([type, id]) => [id, type])
);

function createHeader(fileType, fileName, dataSize) {
  const header = new Uint8Array(HEADER_SIZE);
  const view = new DataView(header.buffer);
  
  // Version
  view.setUint32(0, FILE_FORMAT_VERSION, true);
  
  // Type de fichier
  const typeId = FILE_TYPES[fileType] || FILE_TYPES['application/octet-stream'];
  view.setUint32(4, typeId, true);
  
  // Nom du fichier (UTF-8, max 32 octets)
  const encoder = new TextEncoder();
  const fileNameBytes = encoder.encode(fileName);
  header.set(fileNameBytes, 8);
  
  // Taille des données
  view.setUint32(40, dataSize, true);
  
  return header;
}

function parseHeader(header) {
  const view = new DataView(header.buffer);
  
  // Vérifier la version
  const version = view.getUint32(0, true);
  if (version !== FILE_FORMAT_VERSION) {
    throw new Error('Version de format non supportée');
  }
  
  // Lire le type de fichier
  const typeId = view.getUint32(4, true);
  const fileType = FILE_TYPES_REVERSE[typeId] || 'application/octet-stream';
  
  // Lire le nom du fichier
  const decoder = new TextDecoder();
  const fileNameBytes = new Uint8Array(header.buffer, 8, 32);
  let fileName = decoder.decode(fileNameBytes);
  
  // Supprimer tous les caractères nuls et espaces inutiles à la fin
  fileName = fileName.replace(/[\0\s]+$/, '');
  
  // Lire la taille des données
  const dataSize = view.getUint32(40, true);
  
  return { fileType, fileName, dataSize };
}

export async function encrypt(data, password, algorithm, fileType = 'application/octet-stream', fileName = 'file') {
  try {
    // Vérifier que le mot de passe n'est pas vide
    if (!password) {
      throw new Error('La clé secrète ne peut pas être vide');
    }
    
    // Vérifier que les données ne sont pas vides
    if (!data) {
      throw new Error('Les données à chiffrer ne peuvent pas être vides');
    }
    
    // Générer un IV aléatoire
    const iv = crypto.getRandomValues(new Uint8Array(16));
    
    // Générer un sel aléatoire
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Dériver la clé à partir du mot de passe
    const key = await deriveKey(password, ab2str(salt), algorithm);
    
    // Convertir les données en ArrayBuffer si nécessaire
    let dataBuffer;
    if (typeof data === 'string') {
      dataBuffer = str2ab(data);
    } else if (data instanceof ArrayBuffer) {
      dataBuffer = data;
    } else if (data instanceof Uint8Array) {
      dataBuffer = data.buffer;
    } else {
      throw new Error('Type de données non supporté');
    }
    
    // Chiffrer les données
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-CBC',
        iv: iv
      },
      key,
      dataBuffer
    );
    
    // Créer l'en-tête
    const header = createHeader(fileType, fileName, encrypted.byteLength);
    
    // Combiner l'en-tête, le sel, l'IV et les données chiffrées
    const result = new Uint8Array(HEADER_SIZE + salt.length + iv.length + encrypted.byteLength);
    result.set(header, 0);
    result.set(new Uint8Array(salt), HEADER_SIZE);
    result.set(new Uint8Array(iv), HEADER_SIZE + salt.length);
    result.set(new Uint8Array(encrypted), HEADER_SIZE + salt.length + iv.length);
    
    return result.buffer;
  } catch (error) {
    throw new Error(`Erreur de chiffrement: ${error.message}`);
  }
}

export async function decrypt(encryptedData, password, algorithm) {
  try {
    if (!(encryptedData instanceof ArrayBuffer)) {
      throw new Error('Format de données non supporté');
    }
    
    const data = new Uint8Array(encryptedData);
    
    // Vérifier la taille minimale
    if (data.length < HEADER_SIZE + 32) { // En-tête + sel + IV
      throw new Error('Données chiffrées invalides');
    }
    
    // Lire l'en-tête
    const header = data.slice(0, HEADER_SIZE);
    const { fileType, fileName, dataSize } = parseHeader(header);
    
    // Extraire le sel, l'IV et les données chiffrées
    const salt = data.slice(HEADER_SIZE, HEADER_SIZE + 16);
    const iv = data.slice(HEADER_SIZE + 16, HEADER_SIZE + 32);
    const encrypted = data.slice(HEADER_SIZE + 32, HEADER_SIZE + 32 + dataSize);
    
    // Vérifier que le mot de passe n'est pas vide
    if (!password) {
      throw new Error('La clé secrète ne peut pas être vide');
    }
    
    // Dériver la clé à partir du mot de passe
    const key = await deriveKey(password, ab2str(salt), algorithm);
    
    // Déchiffrer les données
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: iv
      },
      key,
      encrypted
    );
    
    return {
      content: decrypted,
      type: fileType,
      name: fileName
    };
  } catch (error) {
    throw new Error(`Erreur de déchiffrement: ${error.message}`);
  }
} 