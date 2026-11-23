import { useState, useMemo, useCallback } from 'react';
import { encryptFile, decryptFile, inspectFile, ENCRYPTED_EXTENSION } from '../utils/cryptoUtils';
import FileDropZone from './FileDropZone';

const LEGACY_ALGORITHMS = [
  { value: 'auto', label: 'Détection automatique (recommandé)' },
  { value: 'aes-256-cbc', label: 'AES-256-CBC' },
  { value: 'aes-192-cbc', label: 'AES-192-CBC' },
  { value: 'aes-128-cbc', label: 'AES-128-CBC' },
];

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(1)} Mo`;
}

async function saveBytes(name, content, type) {
  if (window.securio?.saveFile) {
    return window.securio.saveFile(name, content);
  }
  // Navigateur (npm run dev) : téléchargement classique
  const blob = new Blob([content], { type: type || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return name;
}

function EncryptForm({ initialFile }) {
  const [file, setFile] = useState(null);
  const [key, setKey] = useState('');
  const [confirmKey, setConfirmKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [legacyAlgorithm, setLegacyAlgorithm] = useState('auto');
  const [forceEncrypt, setForceEncrypt] = useState(false);
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const info = useMemo(() => (file ? inspectFile(file.content) : null), [file]);
  const mode = info && !forceEncrypt ? 'decrypt' : 'encrypt';

  const loadFile = useCallback((fileData) => {
    setFile(fileData);
    setResult(null);
    setError('');
    setNotice('');
    setForceEncrypt(false);
    setConfirmKey('');
  }, []);

  // Fichier reçu depuis le système (double-clic sur un .encrypted)
  const [lastInitialFile, setLastInitialFile] = useState(null);
  if (initialFile && initialFile !== lastInitialFile) {
    setLastInitialFile(initialFile);
    loadFile(initialFile);
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setNotice('');
    setResult(null);

    if (!file) return setError('Veuillez sélectionner un fichier.');
    if (!key) return setError('Veuillez entrer une clé secrète.');
    if (mode === 'encrypt' && key !== confirmKey) {
      return setError('Les deux clés saisies ne correspondent pas.');
    }

    setIsLoading(true);
    try {
      if (mode === 'encrypt') {
        const encrypted = await encryptFile(file.content, key, { name: file.name, type: file.type });
        setResult({
          content: encrypted,
          type: 'application/octet-stream',
          name: `${file.name}${ENCRYPTED_EXTENSION}`,
          warnings: [],
          alternatives: [],
        });
      } else {
        const decrypted = await decryptFile(file.content, key, {
          algorithm: legacyAlgorithm,
          outerName: file.name,
        });
        setResult(decrypted);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSave = async (item) => {
    try {
      const saved = await saveBytes(item.name, item.content, item.type);
      if (saved) setNotice(`Enregistré : ${saved}`);
    } catch (err) {
      setError(`Enregistrement impossible : ${err.message}`);
    }
  };

  const weakKey = mode === 'encrypt' && key.length > 0 && key.length < 10;

  return (
    <div className="max-w-4xl mx-auto p-4">
      <form className="bg-white rounded-lg shadow-lg p-6" onSubmit={handleSubmit}>
        <h2 className="text-2xl font-bold mb-6">Chiffrement/Déchiffrement de fichiers</h2>

        <div className="space-y-6">
          <div>
            <span className="block text-sm font-medium text-gray-700 mb-2">Fichier à traiter</span>
            <FileDropZone onFileDrop={loadFile} onError={setError} />
            {file && (
              <div className="mt-2 text-sm text-gray-600 space-y-1">
                <div>
                  Fichier sélectionné : <strong>{file.name}</strong> ({formatSize(file.content.length)})
                </div>
                {info?.format === 'v2' && !forceEncrypt && (
                  <div className="text-green-700">Fichier Securio (format v2, AES-256-GCM authentifié).</div>
                )}
                {info?.format === 'v1' && !forceEncrypt && (
                  <div className="text-amber-700">
                    Fichier Securio ancien format (v1, ≤ 1.2.1) : lu en mode compatibilité.
                  </div>
                )}
                {info && (
                  <button
                    type="button"
                    className="text-xs text-blue-600 underline"
                    onClick={() => {
                      setForceEncrypt((v) => !v);
                      setResult(null);
                    }}
                  >
                    {forceEncrypt ? 'Revenir au déchiffrement' : 'Chiffrer ce fichier une seconde fois'}
                  </button>
                )}
              </div>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor="key">
              Clé secrète
            </label>
            <div className="flex gap-2">
              <input
                id="key"
                type={showKey ? 'text' : 'password'}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="Entrez votre clé secrète"
                autoComplete="off"
              />
              <button
                type="button"
                className="px-3 border rounded-md text-sm text-gray-600"
                onClick={() => setShowKey((v) => !v)}
              >
                {showKey ? 'Masquer' : 'Afficher'}
              </button>
            </div>
            {weakKey && (
              <p className="mt-1 text-xs text-amber-700">
                Clé courte : préférez au moins 10 caractères (ou une phrase de passe).
              </p>
            )}
          </div>

          {mode === 'encrypt' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor="confirmKey">
                Confirmer la clé
              </label>
              <input
                id="confirmKey"
                type={showKey ? 'text' : 'password'}
                value={confirmKey}
                onChange={(e) => setConfirmKey(e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="Saisissez à nouveau la clé"
                autoComplete="off"
              />
              <p className="mt-1 text-xs text-gray-500">
                Aucune récupération n'est possible en cas d'oubli de la clé.
              </p>
            </div>
          )}

          {mode === 'decrypt' && info?.format === 'v1' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor="algo">
                Algorithme utilisé à l'époque
              </label>
              <select
                id="algo"
                value={legacyAlgorithm}
                onChange={(e) => setLegacyAlgorithm(e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
              >
                {LEGACY_ALGORITHMS.map((a) => (
                  <option key={a.value} value={a.value}>
                    {a.label}
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading || !file}
            className={`w-full text-white py-2 px-4 rounded-md disabled:opacity-50 ${
              mode === 'encrypt' ? 'bg-blue-600 hover:bg-blue-700' : 'bg-green-600 hover:bg-green-700'
            }`}
          >
            {isLoading ? 'Traitement en cours…' : mode === 'encrypt' ? 'Chiffrer' : 'Déchiffrer'}
          </button>

          {error && <div className="text-red-600 text-sm">Erreur : {error}</div>}
          {notice && <div className="text-green-700 text-sm break-all">{notice}</div>}

          {result && (
            <div className="mt-4 p-3 border rounded-md bg-gray-50 space-y-3">
              <div className="flex justify-between items-center gap-4">
                <div className="text-sm text-gray-700 break-all">
                  <div className="font-medium">{result.name}</div>
                  <div className="text-xs text-gray-500">
                    {formatSize(result.content.length)}
                    {result.format && ` · format ${result.format}`}
                    {result.algorithm && ` · ${result.algorithm.toUpperCase()}`}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleSave(result)}
                  className="shrink-0 bg-gray-700 text-white py-1 px-3 rounded-md hover:bg-gray-800"
                >
                  Sauvegarder
                </button>
              </div>

              {result.warnings?.length > 0 && (
                <ul className="text-xs text-amber-800 list-disc pl-5 space-y-1">
                  {result.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              )}

              {result.alternatives?.map((alt) => (
                <div key={alt.label} className="flex justify-between items-center text-xs text-gray-600">
                  <span>{alt.label}</span>
                  <button
                    type="button"
                    onClick={() => handleSave(alt)}
                    className="border border-gray-400 py-0.5 px-2 rounded-md hover:bg-gray-100"
                  >
                    Sauvegarder cette version
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </form>
    </div>
  );
}

export default EncryptForm;
