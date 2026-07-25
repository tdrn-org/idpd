<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Shield } from '@lucide/svelte';

  let { children }: { children: Snippet } = $props();
</script>

<nav class="glass sticky top-0 z-50 px-6 py-3 flex items-center gap-3">
  <a href="/" class="flex items-center gap-2 text-indigo-400 hover:text-indigo-300 transition-colors">
    <Shield class="w-6 h-6" />
    <span class="font-semibold text-lg">IdPD</span>
  </a>
  <div class="flex-1"></div>
</nav>

<main class="max-w-2xl mx-auto px-4 py-12">
  {@render children()}
</main>
