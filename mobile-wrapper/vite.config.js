import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = dirname(fileURLToPath(import.meta.url));

// https://vitejs.dev/config/
export default defineConfig({
  root: projectRoot,
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false
      },
      '/static': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      input: {
        main: resolve(projectRoot, 'index.html')
      },
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          three: ['three']
        }
      }
    }
  },
  resolve: {
    alias: {
      '@': resolve(projectRoot, './src'),
      '@components': resolve(projectRoot, './src/components'),
      '@pages': resolve(projectRoot, './src/pages'),
      '@api': resolve(projectRoot, './src/api'),
      '@styles': resolve(projectRoot, './src/styles'),
      '@assets': resolve(projectRoot, './src/assets'),
      '@three': resolve(projectRoot, './src/three')
    }
  },
  css: {
    modules: {
      localsConvention: 'camelCase'
    }
  },
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-router-dom', 'three']
  }
});
