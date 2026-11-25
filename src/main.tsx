import {createRoot} from 'react-dom/client';
import {registerSW} from 'virtual:pwa-register';
import App from './App.tsx';
import {ErrorBoundary} from './components/ui/ErrorBoundary.tsx';
import {ToastProvider} from './components/ui/ToastProvider.tsx';
import './hooks/usePWAInstall';
import './index.css';

if (import.meta.env.PROD && typeof window !== 'undefined' && 'serviceWorker' in navigator) {
  registerSW({
    immediate: true,
    onRegisterError: () => {
      // Ignore service worker registration errors in restricted iframe/webview contexts
    },
  });
}

createRoot(document.getElementById('root')!).render(
  <ErrorBoundary>
    <ToastProvider>
      <App />
    </ToastProvider>
  </ErrorBoundary>,
);
