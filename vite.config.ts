import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The browser talks to /api on the same origin; Vite forwards it to the VulnBank server.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1', // this computer only
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:4000', changeOrigin: false },
    },
  },
});
