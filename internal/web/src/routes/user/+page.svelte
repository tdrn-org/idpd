<script lang="ts">
  import { api, m } from '$lib';
  import type { SessionInfo } from '$lib/types.js';
  import { LogOut, User, Loader, TriangleAlert } from '@lucide/svelte';

  let session = $state<SessionInfo | null>(null);
  let loading = $state(true);
  let error = $state('');

  $effect(() => {
    loadSession();
  });

  async function loadSession() {
    try {
      session = await api.session();
    } catch (err) {
      error = err instanceof Error ? err.message : m.error_generic();
    } finally {
      loading = false;
    }
  }
</script>

{#if loading}
  <div class="flex flex-col items-center justify-center min-h-[40vh] gap-4">
    <Loader class="w-8 h-8 text-indigo-400 animate-spin" />
    <p class="text-stone-400">{m.loading()}</p>
  </div>
{:else if error || !session}
  <div class="card p-8 max-w-md mx-auto space-y-6 text-center">
    <TriangleAlert class="w-12 h-12 text-amber-400 mx-auto" />
    <p class="text-amber-400">{error || m.error_generic()}</p>
    <a href="/" class="text-indigo-400 hover:text-indigo-300">{m.back_home()}</a>
  </div>
{:else}
  <div class="card p-8 max-w-md mx-auto space-y-6">
    <!-- Avatar + Greeting -->
    <div class="flex flex-col items-center gap-4">
      {#if session.user.picture}
        <img
          src="data:image/jpeg;base64,{session.user.picture}"
          alt={session.user.nickname || session.user.name}
          class="w-24 h-24 rounded-full object-cover ring-4 ring-indigo-500/30"
        />
      {:else}
        <div class="p-6 rounded-full bg-indigo-500/10">
          <User class="w-16 h-16 text-indigo-400" />
        </div>
      {/if}
      <h1 class="text-2xl font-bold text-white">
        {m.user_welcome().replace('{user}', session.user.nickname || session.user.name || session.user.login)}
      </h1>
    </div>

    <!-- Details -->
    <dl class="space-y-3 pt-4 border-t border-slate-700">
      <div class="flex justify-between gap-4">
        <dt class="text-stone-400">{m.user_login()}</dt>
        <dd class="text-stone-200 font-mono text-sm truncate max-w-[240px]">{session.user.login}</dd>
      </div>

      {#if session.user.email}
        <div class="flex justify-between gap-4">
          <dt class="text-stone-400">E-Mail</dt>
          <dd class="text-stone-200 text-sm truncate max-w-[240px]">{session.user.email}</dd>
        </div>
      {/if}

      {#if session.user.groups.length > 0}
        <div class="flex justify-between gap-4">
          <dt class="text-stone-400">{m.user_groups()}</dt>
          <dd class="text-stone-200 text-sm text-right">
            {session.user.groups.join(', ')}
          </dd>
        </div>
      {/if}
    </dl>

    <!-- Logout -->
    <div class="text-center pt-4">
      <a href="/"
         class="inline-flex items-center gap-2 px-6 py-2 text-stone-400 hover:text-white transition-colors">
        <LogOut class="w-4 h-4" />
        {m.user_logout()}
      </a>
    </div>
  </div>
{/if}
