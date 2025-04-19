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

export async function encrypt(text, password, algorithm) {
  try {
    // Générer un IV aléatoire
    const iv = crypto.getRandomValues(new Uint8Array(16));
    
    // Générer un sel aléatoire
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Dériver la clé à partir du mot de passe
    const key = await deriveKey(password, ab2str(salt), algorithm);
    
    // Chiffrer le texte
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-CBC',
        iv: iv
      },
      key,
      str2ab(text)
    );
    
    // Combiner le sel, l'IV et le texte chiffré
    return `${buf2hex(salt)}:${buf2hex(iv)}:${buf2hex(encrypted)}`;
  } catch (error) {
    throw new Error(`Erreur de chiffrement: ${error.message}`);
  }
}

export async function decrypt(encryptedData, password, algorithm) {
  try {
    // Séparer le sel, l'IV et le texte chiffré
    const [saltHex, ivHex, encryptedHex] = encryptedData.split(':');
    
    // Convertir les données hexadécimales en tableaux d'octets
    const salt = hex2buf(saltHex);
    const iv = hex2buf(ivHex);
    const encrypted = hex2buf(encryptedHex);
    
    // Dériver la clé à partir du mot de passe
    const key = await deriveKey(password, ab2str(salt), algorithm);
    
    // Déchiffrer le texte
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: iv
      },
      key,
      encrypted
    );
    
    return ab2str(decrypted);
  } catch (error) {
    throw new Error(`Erreur de déchiffrement: ${error.message}`);
  }
} 