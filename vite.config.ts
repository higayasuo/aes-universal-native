import { defineConfig } from 'vite';
import { resolve } from 'path';
import dts from 'vite-plugin-dts';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'ExpoAesUniversalNative',
      fileName: (format) => `index.${format === 'es' ? 'mjs' : 'cjs'}`,
      formats: ['es', 'cjs'],
    },
    rollupOptions: {
      external: ['expo-aes-universal', 'expo-crypto-universal', 'node-forge'],
    },
  },
  plugins: [
    dts({
      include: ['src'],
      rollupTypes: true,
    }),
  ],
});
