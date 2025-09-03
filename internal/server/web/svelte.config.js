import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

const config = {
	preprocess: vitePreprocess(),
	kit: { adapter: adapter({
			pages: 'build',
			assets: 'build',
			fallback: undefined,
			precompress: false,
			strict: true
	}),
	prerender: {
		entries: [ '/', '/user', '/user/verify', '/user/totp' ]
	},
	csp: {
		directives: {
			'script-src': ['self']
		},
	} }
};

export default config;
