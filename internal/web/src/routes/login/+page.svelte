<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { api, m } from '$lib';
  import type { SessionLoginInfo } from '$lib/types.js';
  import { LogIn, Loader, TriangleAlert } from '@lucide/svelte';

  let id = $state('');
  let loginInfo = $state<SessionLoginInfo | null>(null);
  let username = $state('');
  let password = $state('');
  let remember = $state(false);
  let loading = $state(true);
  let error = $state('');

  $effect(() => {
    const urlId = $page.url.searchParams.get('id');
    if (urlId) {
      id = urlId;
      loadLoginInfo(urlId);
    } else {
      error = 'Keine Authentifizierungs-ID gefunden.';
      loading = false;
    }
  });

  async function loadLoginInfo(authId: string) {
    try {
      loginInfo = await api.sessionLoginInfo(authId);
    } catch (err) {
      error = 'Login-Informationen konnten nicht geladen werden.';
    } finally {
      loading = false;
    }
  }

  async function handleSubmit(e: Event) {
    e.preventDefault();
    loading = true;
    error = '';
    try {
      const verification = loginInfo?.allowed_verifications?.[0] ?? 'email';
      await api.sessionLogin({
        id,
        login: username,
        password,
        remember,
        verification
      });
      goto(`/verify?id=${encodeURIComponent(id)}`);
    } catch (err) {
      error = err instanceof Error ? err.message : 'Anmeldung fehlgeschlagen.';
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
{:else if error}
  <div class="card p-8 max-w-md mx-auto space-y-6 text-center">
    <TriangleAlert class="w-12 h-12 text-amber-400 mx-auto" />
    <p class="text-amber-400">{error}</p>
    <a href="/" class="text-indigo-400 hover:text-indigo-300">{m.back_home()}</a>
  </div>
{:else}
  <div class="card p-8 max-w-md mx-auto space-y-6">
    <div class="text-center">
      <h1 class="text-2xl font-bold text-white">{m.login_title()}</h1>
      {#if loginInfo?.login_hint}
        <p class="text-stone-400 text-sm mt-1">{loginInfo.login_hint}</p>
      {/if}
    </div>

    <form class="space-y-4" onsubmit={handleSubmit}>
      <div>
        <label for="username" class="block text-sm font-medium text-stone-300 mb-1">{m.login_username()}</label>
        <input
          id="username"
          type="text"
          bind:value={username}
          class="w-full px-4 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-stone-500 focus:outline-none focus:border-indigo-400 focus:ring-1 focus:ring-indigo-400 transition-colors"
          placeholder={m.login_username()}
          required
        />
      </div>

      <div>
        <label for="password" class="block text-sm font-medium text-stone-300 mb-1">{m.login_password()}</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          class="w-full px-4 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-stone-500 focus:outline-none focus:border-indigo-400 focus:ring-1 focus:ring-indigo-400 transition-colors"
          placeholder="••••••••"
          required
        />
      </div>

      {#if loginInfo}
        <label class="flex items-center gap-2 text-sm text-stone-400 cursor-pointer">
          <input type="checkbox" bind:checked={remember}
            class="rounded bg-slate-800 border-slate-600 text-indigo-500 focus:ring-indigo-400" />
          {m.login_remember()}
        </label>
      {/if}

      <button
        type="submit"
        class="w-full flex items-center justify-center gap-2 px-6 py-3 bg-indigo-500 hover:bg-indigo-400 text-white font-medium rounded-lg transition-colors shadow-lg shadow-indigo-500/25"
      >
        <LogIn class="w-5 h-5" />
        {m.login_submit()}
      </button>
    </form>
  </div>
{/if}
