import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import SplashScreen from './pages/SplashScreen';

function App() {
  const [booted, setBooted] = useState(false);

  return (
    <>
      {!booted && <SplashScreen onComplete={() => setBooted(true)} />}
      {booted && <Dashboard />}
    </>
  );
}

export default App;
