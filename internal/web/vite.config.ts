import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import adapter from '@sveltejs/adapter-static';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

// SvelteKit 3 no longer reads svelte.config.js — the project configuration (previously
// `kit.*`) is passed to the sveltekit() plugin, and any option that is not SvelteKit's
// own is forwarded to vite-plugin-svelte (hence `preprocess`).
export default defineConfig({
  plugins: [
    tailwindcss(),
    sveltekit({
      preprocess: vitePreprocess(),
      paths: {
        relative: false,
      },
      adapter: adapter({
        pages: './build',
        assets: './build',
        fallback: 'index.html',
        precompress: false,
        strict: true,
      }),
    }),
  ],
});
