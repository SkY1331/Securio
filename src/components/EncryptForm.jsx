import { useState, useEffect } from 'react';
import { encrypt, decrypt } from '../utils/cryptoUtils';
import FileDropZone from './FileDropZone';

const algorithms = [
  { value: 'aes-256-cbc', label: 'AES-256-CBC' },
  { value: 'aes-192-cbc', label: 'AES-192-CBC' },
  { value: 'aes-128-cbc', label: 'AES-128-CBC' },
];

function EncryptForm({ initialFile }) {
  const [file, setFile] = useState(null);
  const [key, setKey] = useState('');
  const [algorithm, setAlgorithm] = useState('aes-256-cbc');
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (initialFile) {
      setFile(initialFile);
    }
  }, [initialFile]);

  const handleFileDrop = (fileData) => {
    setFile(fileData);
    setResult(null);
    setError('');
  };

  const handleEncrypt = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      if (!file) {
        throw new Error('Veuillez sélectionner un fichier');
      }
      
      if (!key) {
        throw new Error('Veuillez entrer une clé secrète');
      }
      
      const encrypted = await encrypt(
        file.content,
        key,
        algorithm,
        file.type,
        file.name
      );
      
      setResult({
        content: encrypted,
        type: 'application/octet-stream',
        name: `${file.name}.encrypted`
      });
    } catch (error) {
      setError(`Erreur: ${error.message}`);
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDecrypt = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      if (!file) {
        throw new Error('Veuillez sélectionner un fichier');
      }
      
      if (!key) {
        throw new Error('Veuillez entrer une clé secrète');
      }
      
      const decrypted = await decrypt(file.content, key, algorithm);
      setResult(decrypted);
    } catch (error) {
      setError(`Erreur: ${error.message}`);
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSaveResult = () => {
    if (!result) return;

    const blob = new Blob([result.content], { type: result.type || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = result.name || 'fichier';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-4xl mx-auto p-4">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold mb-6">Chiffrement/Déchiffrement de fichiers</h2>
        
        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Fichier à traiter
            </label>
            <FileDropZone onFileDrop={handleFileDrop} />
            {file && (
              <div className="mt-2 text-sm text-gray-600">
                Fichier sélectionné : {file.name}
              </div>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Clé secrète
            </label>
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              className="w-full px-3 py-2 border rounded-md"
              placeholder="Entrez votre clé secrète"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Algorithme
            </label>
            <select
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value)}
              className="w-full px-3 py-2 border rounded-md"
            >
              {algorithms.map((algo) => (
                <option key={algo.value} value={algo.value}>
                  {algo.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex space-x-4">
            <button
              onClick={handleEncrypt}
              disabled={isLoading}
              className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              Chiffrer
            </button>
            <button
              onClick={handleDecrypt}
              disabled={isLoading}
              className="flex-1 bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 disabled:opacity-50"
            >
              Déchiffrer
            </button>
          </div>

          {error && (
            <div className="text-red-600 text-sm">
              {error}
            </div>
          )}

          {result && (
            <div className="mt-4">
              <div className="flex justify-between items-center mb-2">
                <h3 className="text-lg font-medium">Résultat</h3>
                <button
                  onClick={handleSaveResult}
                  className="bg-gray-600 text-white py-1 px-3 rounded-md hover:bg-gray-700"
                >
                  Sauvegarder
                </button>
              </div>
              <div className="w-full h-[calc(100%-2rem)] p-2 border rounded-md bg-gray-50">
                <div className="h-full flex flex-col">
                  <div className="text-xs text-gray-400 mb-1">
                    <span>Nom: {result.name || 'N/A'}</span> | <span>Type: {result.type || 'N/A'}</span>
                  </div>
                  <div className="flex items-center justify-center h-full">
                    <p className="text-gray-500">
                      Fichier binaire - Utilisez le bouton "Sauvegarder" pour télécharger
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default EncryptForm; 