<script lang="ts">
  import { goto } from '$app/navigation';
  import { api, m } from '$lib';
  import { LogIn, Shield, Loader } from '@lucide/svelte';

  let checking = $state(true);
  let hasSession = $state(false);

  $effect(() => {
    api.session()
      .then(session => {
        if (session?.user) {
          hasSession = true;
          goto('/user');
        }
      })
      .catch(err => {
        if (err instanceof Error && err.message.includes('404')) {
          hasSession = false;
        }
        // any other error: stay on landing
      })
      .finally(() => {
        checking = false;
      });
  });
</script>

{#if checking}
  <div class="flex flex-col items-center justify-center min-h-[60vh] gap-4">
    <Loader class="w-8 h-8 text-indigo-400 animate-spin" />
    <p class="text-stone-400">{m.loading()}</p>
  </div>
{:else if !hasSession}
  <div class="flex flex-col items-center justify-center min-h-[60vh] gap-8 text-center">
    <div class="p-6 rounded-full bg-indigo-500/10">
      <Shield class="w-16 h-16 text-indigo-400" />
    </div>

    <div class="space-y-2">
      <h1 class="text-3xl font-bold text-white">{m.landing_title()}</h1>
      <p class="text-stone-400 text-lg">{m.landing_subtitle()}</p>
    </div>

    <a href="/login"
       class="inline-flex items-center gap-2 px-8 py-3 bg-indigo-500 hover:bg-indigo-400 text-white font-medium rounded-lg transition-colors shadow-lg shadow-indigo-500/25">
      <LogIn class="w-5 h-5" />
      {m.landing_cta()}
    </a>
  </div>
{/if}
