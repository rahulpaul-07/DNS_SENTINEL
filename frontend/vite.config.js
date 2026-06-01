import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // In development, proxy to local backend.
  // In production (Vercel), VITE_API_URL will be set to the Render backend URL.
  const backendUrl = process.env.VITE_API_URL || 'http://127.0.0.1:8001';
  const wsBackendUrl = backendUrl.replace(/^http/, 'ws');

  return {
    plugins: [
      tailwindcss(),
      react(),
    ],
    server: {
      proxy: {
        '/api': {
          target: backendUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, '')
        },
        '/ws': {
          target: wsBackendUrl,
          ws: true,
          changeOrigin: true
        }
      }
    }
  }
})

