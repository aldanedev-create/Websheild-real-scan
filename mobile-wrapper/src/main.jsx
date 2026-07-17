import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './styles/global.css';
import './styles/mobile.css';
import './styles/theme.css';

// Register Capacitor plugins
import { registerPlugins } from './config.js';

// Register plugins
registerPlugins();

// Render app
ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);