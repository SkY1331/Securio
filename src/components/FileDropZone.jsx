import { useState, useCallback } from 'react';

function FileDropZone({ onFileDrop, accept = '.txt' }) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragEnter = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files);
    const validFiles = files.filter(file => file.name.endsWith('.txt'));

    if (validFiles.length > 0) {
      const file = validFiles[0];
      const reader = new FileReader();
      
      reader.onload = (event) => {
        onFileDrop(event.target.result);
      };
      
      reader.readAsText(file);
    }
  }, [onFileDrop]);

  return (
    <div
      className={`border-2 border-dashed rounded-lg p-4 sm:p-6 text-center transition-colors ${
        isDragging
          ? 'border-blue-500 bg-blue-50'
          : 'border-gray-300 hover:border-gray-400'
      }`}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <div className="flex flex-col items-center justify-center space-y-2">
        <svg
          className="w-8 h-8 sm:w-12 sm:h-8 text-gray-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
          />
        </svg>
        <p className="text-xs sm:text-sm text-gray-600">
          {isDragging
            ? 'Déposez le fichier ici'
            : 'Glissez-déposez un fichier .txt ici ou cliquez pour sélectionner'}
        </p>
        <input
          type="file"
          accept={accept}
          className="hidden"
          onChange={(e) => {
            const file = e.target.files[0];
            if (file) {
              const reader = new FileReader();
              reader.onload = (event) => {
                onFileDrop(event.target.result);
              };
              reader.readAsText(file);
            }
          }}
        />
      </div>
    </div>
  );
}

export default FileDropZone; 