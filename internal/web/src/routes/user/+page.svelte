<script lang="ts">
  import { m } from '$lib';
  import { LogOut, User } from '@lucide/svelte';
</script>

<div class="card p-8 max-w-md mx-auto space-y-6 text-center">
  <div class="p-6 rounded-full bg-indigo-500/10 inline-block">
    <User class="w-16 h-16 text-indigo-400" />
  </div>

  <h1 class="text-2xl font-bold text-white">{m.user_title()}</h1>
  <p class="text-stone-400">{m.user_welcome().replace('{user}', '...')}</p>

  <a href="/"
     class="inline-flex items-center gap-2 px-6 py-2 text-stone-400 hover:text-white transition-colors">
    <LogOut class="w-4 h-4" />
    {m.user_logout()}
  </a>
</div>
