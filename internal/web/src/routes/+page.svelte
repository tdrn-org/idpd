<script lang="ts">
  import { goto } from '$app/navigation';
  import { enhance } from '$app/forms';
  import { api, m } from '$lib';
  import { LogIn, FingerprintPattern, Loader } from '@lucide/svelte';

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
        // other errors: stay on landing
      })
      .finally(() => {
        checking = false;
      });
  });

  async function handleLogin() {
    try {
      await api.startSession();
    } catch (err) {
      // If the redirect doesn't happen via API, navigate manually
      console.error('Session start failed:', err);
    }
  }
</script>

{#if checking}
  <div class="flex flex-col items-center justify-center min-h-[60vh] gap-4">
    <Loader class="w-8 h-8 text-indigo-400 animate-spin" />
    <p class="text-stone-400">{m.loading()}</p>
  </div>
{:else if !hasSession}
  <div class="flex flex-col items-center justify-center min-h-[60vh] gap-8 text-center">
    <div class="p-6 rounded-full bg-indigo-500/10">
      <FingerprintPattern class="w-16 h-16 text-indigo-400" />
    </div>

    <div class="space-y-2">
      <h1 class="text-3xl font-bold text-white">{m.landing_title()}</h1>
      <p class="text-stone-400 text-lg">{m.landing_subtitle()}</p>
    </div>

    <!-- POST /api/session to initiate Forward-Auth -->
    <form action="/api/session" method="POST" use:enhance>
      <button type="submit"
         class="inline-flex items-center gap-2 px-8 py-3 bg-indigo-500 hover:bg-indigo-400 text-white font-medium rounded-lg transition-colors shadow-lg shadow-indigo-500/25 cursor-pointer">
        <LogIn class="w-5 h-5" />
        {m.landing_cta()}
      </button>
    </form>
  </div>
{/if}
