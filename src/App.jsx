import EncryptForm from './components/EncryptForm';

function App() {
  return (
    <div className="min-h-screen bg-gray-100 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-xl font-bold text-gray-800">Securio</h1>
          <p className="mt-2 text-sm text-gray-600">
            Une petite application autonome pour chiffrer/déchiffrer vos textes et fichiers (v1.0.0)
          </p>
        </div>
        <EncryptForm />
      </div>
    </div>
  );
}

export default App;