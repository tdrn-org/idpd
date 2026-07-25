<script lang="ts">
  import { m } from '$lib';
  import { LogIn } from '@lucide/svelte';

  let username = $state('');
  let password = $state('');
  let otp = $state('');
</script>

<div class="card p-8 max-w-md mx-auto space-y-6">
  <h1 class="text-2xl font-bold text-white text-center">{m.login_title()}</h1>

  <form class="space-y-4" onsubmit={(e) => e.preventDefault()}>
    <div>
      <label for="username" class="block text-sm font-medium text-stone-300 mb-1">{m.login_username()}</label>
      <input
        id="username"
        type="text"
        bind:value={username}
        class="w-full px-4 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-stone-500 focus:outline-none focus:border-indigo-400 focus:ring-1 focus:ring-indigo-400 transition-colors"
        placeholder={m.login_username()}
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
      />
    </div>

    <div>
      <label for="otp" class="block text-sm font-medium text-stone-300 mb-1">{m.login_otp()}</label>
      <input
        id="otp"
        type="text"
        bind:value={otp}
        class="w-full px-4 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-stone-500 focus:outline-none focus:border-indigo-400 focus:ring-1 focus:ring-indigo-400 transition-colors"
        placeholder="123456"
      />
    </div>

    <button
      type="submit"
      class="w-full flex items-center justify-center gap-2 px-6 py-3 bg-indigo-500 hover:bg-indigo-400 text-white font-medium rounded-lg transition-colors shadow-lg shadow-indigo-500/25"
    >
      <LogIn class="w-5 h-5" />
      {m.login_submit()}
    </button>
  </form>

  <p class="text-stone-500 text-xs text-center">Dummy — noch ohne Backend-Anbindung</p>
</div>
