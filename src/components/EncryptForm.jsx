import { useState } from 'react';
import { encrypt, decrypt } from '../utils/cryptoUtils';
import FileDropZone from './FileDropZone';

const algorithms = [
  { value: 'aes-256-cbc', label: 'AES-256-CBC' },
  { value: 'aes-192-cbc', label: 'AES-192-CBC' },
  { value: 'aes-128-cbc', label: 'AES-128-CBC' },
];

function EncryptForm() {
  const [file, setFile] = useState(null);
  const [key, setKey] = useState('');
  const [algorithm, setAlgorithm] = useState('aes-256-cbc');
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

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

    let blob;
    if (result.type.startsWith('text/')) {
      blob = new Blob([result.content], { type: result.type });
    } else if (result.type.startsWith('image/')) {
      const base64Data = result.content.split(',')[1];
      const binaryData = atob(base64Data);
      const array = new Uint8Array(binaryData.length);
      for (let i = 0; i < binaryData.length; i++) {
        array[i] = binaryData.charCodeAt(i);
      }
      blob = new Blob([array], { type: result.type });
    } else {
      blob = new Blob([result.content], { type: result.type });
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = result.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-white p-4 sm:p-6 rounded-lg shadow-md">
      <div className="space-y-4">
        {error && (
          <div className="bg-red-50 text-red-500 p-3 rounded-md">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Fichier
              </label>
              <FileDropZone onFileDrop={handleFileDrop} />
              {file && (
                <div className="mt-2 p-2 bg-gray-50 rounded-md">
                  <p className="text-sm text-gray-600">
                    Fichier sélectionné: {file.name}
                  </p>
                  <p className="text-xs text-gray-500">
                    Type: {file.type}
                  </p>
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Clé secrète
              </label>
              <input
                type="text"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                className="w-full p-2 border rounded-md"
                placeholder="Entrez votre clé secrète"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Algorithme
              </label>
              <select
                value={algorithm}
                onChange={(e) => setAlgorithm(e.target.value)}
                className="w-full p-2 border rounded-md"
              >
                {algorithms.map((algo) => (
                  <option key={algo.value} value={algo.value}>
                    {algo.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex flex-row gap-2">
              <button
                onClick={handleEncrypt}
                disabled={isLoading || !file}
                className={`flex-1 py-2 px-4 rounded-md text-white ${
                  isLoading || !file
                    ? 'bg-blue-300 cursor-not-allowed'
                    : 'bg-blue-500 hover:bg-blue-600'
                }`}
              >
                {isLoading ? 'Chiffrement...' : 'Chiffrer'}
              </button>
              <button
                onClick={handleDecrypt}
                disabled={isLoading || !file}
                className={`flex-1 py-2 px-4 rounded-md text-white ${
                  isLoading || !file
                    ? 'bg-green-300 cursor-not-allowed'
                    : 'bg-green-500 hover:bg-green-600'
                }`}
              >
                {isLoading ? 'Déchiffrement...' : 'Déchiffrer'}
              </button>
            </div>
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="block text-sm font-medium text-gray-700">
                Résultat
              </label>
              {result && (
                <button
                  onClick={handleSaveResult}
                  className="text-sm text-blue-500 hover:text-blue-600 flex items-center gap-1"
                >
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                    />
                  </svg>
                  Sauvegarder
                </button>
              )}
            </div>
            <div className="w-full h-[calc(100%-2rem)] p-2 border rounded-md bg-gray-50">
              {result && (
                <div className="h-full flex flex-col">
                  {result.type.startsWith('image/') ? (
                    <img
                      src={result.content}
                      alt="Résultat"
                      className="max-h-full max-w-full object-contain mx-auto"
                    />
                  ) : result.type.startsWith('text/') ? (
                    <textarea
                      value={result.content}
                      readOnly
                      className="w-full h-full p-2 bg-transparent resize-none"
                    />
                  ) : (
                    <div className="flex items-center justify-center h-full">
                      <p className="text-gray-500">
                        Fichier binaire - Utilisez le bouton "Sauvegarder" pour télécharger
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default EncryptForm; 