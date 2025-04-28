import { useState, useEffect } from 'react';
import EncryptForm from './components/EncryptForm';

function App() {
  const [initialFile, setInitialFile] = useState(null);

  useEffect(() => {
    // Vérifier si un fichier .encrypted a été passé en argument
    const args = window.electron?.ipcRenderer?.sendSync('get-args') || [];
    const encryptedFile = args.find(arg => arg.endsWith('.encrypted'));
    
    if (encryptedFile) {
      // Lire le fichier
      const reader = new FileReader();
      fetch(encryptedFile)
        .then(response => response.blob())
        .then(blob => {
          reader.readAsArrayBuffer(blob);
          reader.onload = (event) => {
            setInitialFile({
              content: event.target.result,
              type: 'application/octet-stream',
              name: encryptedFile.split('/').pop()
            });
          };
        })
        .catch(error => {
          console.error('Erreur lors du chargement du fichier:', error);
        });
    }
  }, []);

  return (
    <div className="min-h-screen bg-gray-100 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-xl font-bold text-gray-800">Securio</h1>
          <p className="mt-2 text-sm text-gray-600">
            Une petite application autonome pour chiffrer/déchiffrer vos textes et fichiers (v1.2.1)
          </p>
        </div>
        <EncryptForm initialFile={initialFile} />
      </div>
    </div>
  );
}

export default App;