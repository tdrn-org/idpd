<script lang="ts">
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { api, m } from '$lib';
  import type { SessionVerifyInfo } from '$lib/types.js';
  import { ShieldCheck, Loader, TriangleAlert } from '@lucide/svelte';

  let id = $state('');
  let verifyInfo = $state<SessionVerifyInfo | null>(null);
  let code = $state('');
  let loading = $state(true);
  let error = $state('');

  $effect(() => {
    const authId = page.params.id;
    if (authId) {
      id = authId;
      loadVerifyInfo(authId);
    } else {
      error = 'Keine Authentifizierungs-ID gefunden.';
      loading = false;
    }
  });

  async function loadVerifyInfo(authId: string) {
    try {
      verifyInfo = await api.sessionVerifyInfo(authId);
    } catch (err) {
      error = 'Verifikationsinformationen konnten nicht geladen werden.';
    } finally {
      loading = false;
    }
  }

  async function handleSubmit(e: Event) {
    e.preventDefault();
    loading = true;
    error = '';
    try {
      await api.sessionVerify(id, { response: code });
      goto('/');
    } catch (err) {
      error = err instanceof Error ? err.message : 'Verifikation fehlgeschlagen.';
    } finally {
      loading = false;
    }
  }

  function verificationLabel(): string {
    switch (verifyInfo?.verification) {
      case 'email': return m.verify_email_label();
      case 'totp': return m.verify_totp_label();
      case 'passkey': return m.verify_passkey_label();
      case 'seckey': return m.verify_seckey_label();
      default: return m.verify_code_label();
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
  <div class="card p-8 max-w-md mx-auto space-y-6 text-center">
    <div class="p-4 rounded-full bg-indigo-500/10 inline-block">
      <ShieldCheck class="w-12 h-12 text-indigo-400" />
    </div>

    <div>
      <h1 class="text-2xl font-bold text-white">{m.verify_title()}</h1>
      <p class="text-stone-400 mt-2">{verificationLabel()}</p>
    </div>

    <form class="space-y-4 text-left" onsubmit={handleSubmit}>
      <div>
        <label for="code" class="block text-sm font-medium text-stone-300 mb-1">{m.verify_code_label()}</label>
        <input
          id="code"
          type="text"
          inputmode="numeric"
          autocomplete="one-time-code"
          bind:value={code}
          class="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white text-center text-2xl tracking-widest placeholder-stone-500 focus:outline-none focus:border-indigo-400 focus:ring-1 focus:ring-indigo-400 transition-colors"
          placeholder="000000"
          maxlength="6"
          required
        />
      </div>

      <button
        type="submit"
        class="w-full flex items-center justify-center gap-2 px-6 py-3 bg-indigo-500 hover:bg-indigo-400 text-white font-medium rounded-lg transition-colors shadow-lg shadow-indigo-500/25"
      >
        <ShieldCheck class="w-5 h-5" />
        {m.verify_submit()}
      </button>
    </form>

    <a href="/login/{id}" class="text-stone-500 hover:text-stone-300 text-sm transition-colors">{m.back_to_login()}</a>
  </div>
{/if}
