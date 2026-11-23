import { useState, useCallback, useId } from 'react';

// Lit TOUJOURS le fichier en binaire (ArrayBuffer).
// Les versions ≤ 1.2.1 lisaient les images en data-URL et les .txt en texte,
// ce qui altérait le contenu chiffré (voir src/utils/legacyV1.js).
async function readFile(file) {
  const buffer = await file.arrayBuffer();
  return {
    content: new Uint8Array(buffer),
    type: file.type || 'application/octet-stream',
    name: file.name,
  };
}

function FileDropZone({ onFileDrop, onError }) {
  const [isDragging, setIsDragging] = useState(false);
  const inputId = useId();

  const handleFiles = useCallback(
    async (fileList) => {
      const file = fileList?.[0];
      if (!file) return;
      try {
        onFileDrop(await readFile(file));
      } catch (e) {
        onError?.(`Impossible de lire le fichier : ${e.message}`);
      }
    },
    [onFileDrop, onError]
  );

  const stop = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  return (
    <label
      htmlFor={inputId}
      className={`block cursor-pointer border-2 border-dashed rounded-lg p-4 sm:p-6 text-center transition-colors ${
        isDragging ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400'
      }`}
      onDragEnter={(e) => {
        stop(e);
        setIsDragging(true);
      }}
      onDragLeave={(e) => {
        stop(e);
        setIsDragging(false);
      }}
      onDragOver={stop}
      onDrop={(e) => {
        stop(e);
        setIsDragging(false);
        handleFiles(e.dataTransfer.files);
      }}
    >
      <div className="flex flex-col items-center justify-center space-y-2">
        <svg
          className="w-8 h-8 sm:w-12 sm:h-8 text-gray-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
          />
        </svg>
        <p className="text-xs sm:text-sm text-gray-600">
          {isDragging ? 'Déposez le fichier ici' : 'Glissez-déposez un fichier ici ou cliquez pour sélectionner'}
        </p>
        <input
          id={inputId}
          type="file"
          className="hidden"
          onChange={(e) => {
            handleFiles(e.target.files);
            e.target.value = ''; // permet de re-sélectionner le même fichier
          }}
        />
      </div>
    </label>
  );
}

export default FileDropZone;
