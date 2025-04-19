import { useState } from 'react';
import { encrypt, decrypt } from '../utils/cryptoUtils';
import FileDropZone from './FileDropZone';

const algorithms = [
  { value: 'aes-256-cbc', label: 'AES-256-CBC' },
  { value: 'aes-192-cbc', label: 'AES-192-CBC' },
  { value: 'aes-128-cbc', label: 'AES-128-CBC' },
];

function EncryptForm() {
  const [content, setContent] = useState('');
  const [key, setKey] = useState('');
  const [algorithm, setAlgorithm] = useState('aes-256-cbc');
  const [result, setResult] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleFileDrop = (fileContent) => {
    setContent(fileContent);
  };

  const handleEncrypt = async () => {
    try {
      setIsLoading(true);
      setError('');
      const encrypted = await encrypt(content, key, algorithm);
      setResult(encrypted);
    } catch (error) {
      setError(`Erreur: ${error.message}`);
      setResult('');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDecrypt = async () => {
    try {
      setIsLoading(true);
      setError('');
      const decrypted = await decrypt(content, key, algorithm);
      setResult(decrypted);
    } catch (error) {
      setError(`Erreur: ${error.message}`);
      setResult('');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSaveResult = () => {
    if (!result) return;

    const blob = new Blob([result], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'result.txt';
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
                Contenu
              </label>
              <FileDropZone onFileDrop={handleFileDrop} />
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                className="w-full h-32 p-2 border rounded-md mt-2 resize-none"
                placeholder="Ou entrez le texte à chiffrer ou déchiffrer"
              />
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
                disabled={isLoading}
                className={`flex-1 py-2 px-4 rounded-md text-white ${
                  isLoading
                    ? 'bg-blue-300 cursor-not-allowed'
                    : 'bg-blue-500 hover:bg-blue-600'
                }`}
              >
                {isLoading ? 'Chiffrement...' : 'Chiffrer'}
              </button>
              <button
                onClick={handleDecrypt}
                disabled={isLoading}
                className={`flex-1 py-2 px-4 rounded-md text-white ${
                  isLoading
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
            <textarea
              value={result}
              readOnly
              className="w-full h-[calc(100%-2rem)] p-2 border rounded-md bg-gray-50 resize-none"
            />
          </div>
        </div>
      </div>
    </div>
  );
}

export default EncryptForm; 