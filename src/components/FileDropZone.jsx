import { useEffect, useState } from 'react';
import { onDragDrop, pickFiles, pickFolder } from '../api';

// Zone de dépôt : on ne récupère que des CHEMINS ; c'est le cœur Rust qui lit les
// fichiers, en flux, sans les charger dans l'interface.
function FileDropZone({ onPaths, disabled }) {
  const [isDragging, setIsDragging] = useState(false);

  useEffect(() => {
    let unlisten;
    let cancelled = false;
    onDragDrop((event) => {
      if (event.type === 'enter' || event.type === 'over') setIsDragging(true);
      else if (event.type === 'leave') setIsDragging(false);
      else if (event.type === 'drop') {
        setIsDragging(false);
        if (!disabled && event.paths?.length) onPaths(event.paths);
      }
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [onPaths, disabled]);

  const chooseFiles = async () => {
    const paths = await pickFiles();
    if (paths.length) onPaths(paths);
  };
  const chooseFolder = async () => {
    const path = await pickFolder('Choisir un dossier à chiffrer');
    if (path) onPaths([path]);
  };

  return (
    <div
      className={`w-full border-2 border-dashed rounded-lg p-4 sm:p-6 text-center transition-colors ${
        isDragging ? 'border-blue-500 bg-blue-50' : 'border-gray-300'
      } ${disabled ? 'opacity-50' : ''}`}
    >
      <div className="flex flex-col items-center justify-center space-y-3">
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
          {isDragging ? 'Déposez ici' : 'Glissez-déposez des fichiers ou des dossiers ici'}
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={disabled}
            onClick={chooseFiles}
            className="px-3 py-1 text-sm border rounded-md text-gray-700 hover:bg-gray-50"
          >
            Choisir des fichiers…
          </button>
          <button
            type="button"
            disabled={disabled}
            onClick={chooseFolder}
            className="px-3 py-1 text-sm border rounded-md text-gray-700 hover:bg-gray-50"
          >
            Choisir un dossier…
          </button>
        </div>
      </div>
    </div>
  );
}

export default FileDropZone;
