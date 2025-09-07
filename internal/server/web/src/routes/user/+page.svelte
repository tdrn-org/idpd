<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Fingerprint } from '@lucide/svelte';
	import session from '$lib/session';
	import Anonymous from '$lib/components/Anonymous.svelte';

	let id: string | null;
	let subject: string = '';
	let password: string = '';
	let verification: string = '';
	let remember: boolean = false;

	onMount(() => {
		id = page.url.searchParams.get('id');
		if (!id) {
			session.restartLogin();
		}
	});
</script>

<section class="bg-gray-50 dark:bg-gray-900">
	<div class="mx-auto flex flex-col items-center justify-center px-6 py-8 md:h-screen lg:py-0">
		{#await session.fetchUserInfo() then userInfo}
			<div class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white">
				<Fingerprint size={24} />&nbsp;Login
			</div>
			<div
				class="w-full rounded-lg bg-white shadow sm:max-w-md md:mt-0 xl:p-0 dark:border dark:border-gray-700 dark:bg-gray-800"
			>
				<div class="space-y-4 p-6 sm:p-8 md:space-y-6">
					<h1
						class="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl dark:text-white"
					>
						Confirm login
					</h1>
					<form class="space-y-4 md:space-y-6" action="/session/authenticate" method="post">
						<input type="hidden" name="id" value={id} />
						<div>
							<label
								for="subject"
								class="mb-2 block text-sm font-medium text-gray-900 dark:text-white"
								>Your login</label
							>
							<input
								type="input"
								name="subject"
								id="subject"
								class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
								placeholder="Enter your login name"
								bind:value={subject}
								required
							/>
						</div>
						<div>
							<label
								for="password"
								class="mb-2 block text-sm font-medium text-gray-900 dark:text-white">Password</label
							>
							<input
								type="password"
								name="password"
								id="password"
								class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
								placeholder="••••••••"
								bind:value={password}
								required
							/>
						</div>
						<div>
							<label
								for="verification"
								class="mb-2 block text-sm font-medium text-gray-900 dark:text-white"
								>Verification (2FA)</label
							>
							<select
								name="verification"
								id="verification"
								class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
								bind:value={verification}
								required
							>
								<option value="" selected>Select verification method</option>
								<option value="email">Email code</option>
								<option value="totp">TOTP code</option>
								<option value="passkey">Passkey</option>
								<option value="webauthn">WebAuthn</option>
							</select>
						</div>
						<div class="flex items-center justify-between">
							<div class="flex items-start">
								<div class="flex h-5 items-center">
									<input
										type="checkbox"
										name="remember"
										id="remember"
										value="true"
										aria-describedby="remember"
										class="focus:ring-3 focus:ring-primary-300 dark:focus:ring-primary-600 h-4 w-4 rounded border border-gray-300 bg-gray-50 dark:border-gray-600 dark:bg-gray-700 dark:ring-offset-gray-800"
										bind:checked={remember}
									/>
								</div>
								<div class="ml-3 text-sm">
									<label for="remember" class="text-gray-500 dark:text-gray-300">Remember me</label>
								</div>
							</div>
						</div>
						<button
							type="submit"
							class="bg-primary-600 hover:bg-primary-700 focus:ring-primary-300 dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 w-full rounded-lg px-5 py-2.5 text-center text-sm font-medium text-white focus:outline-none focus:ring-4"
							>Sign in</button
						>
					</form>
					<div class="flex items-center justify-between">
						<a
							class="button w-full rounded-lg bg-gray-600 px-5 py-2.5 text-center text-sm font-medium text-white hover:bg-gray-700 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:bg-gray-600 dark:hover:bg-gray-700 dark:focus:ring-gray-800"
							href="/">Cancel</a
						>
					</div>
				</div>
			</div>
		{:catch}
			<div class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white">
				<Fingerprint size={24} />&nbsp;Login
			</div>
			<div
				class="w-full rounded-lg bg-white shadow sm:max-w-md md:mt-0 xl:p-0 dark:border dark:border-gray-700 dark:bg-gray-800"
			>
				<div class="space-y-4 p-6 sm:p-8 md:space-y-6">
					<h1
						class="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl dark:text-white"
					>
						Sign in to your account
					</h1>
					<form class="space-y-4 md:space-y-6" action="/session/authenticate" method="post">
						<input type="hidden" name="id" value={id} />
						<div>
							<label
								for="subject"
								class="mb-2 block text-sm font-medium text-gray-900 dark:text-white"
								>Your login</label
							>
							<input
								type="input"
								name="subject"
								id="subject"
								class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
								placeholder="Enter your login name"
								bind:value={subject}
								required
							/>
						</div>
						<div>
							<label
								for="password"
								class="mb-2 block text-sm font-medium text-gray-900 dark:text-white">Password</label
							>
							<input
								type="password"
								name="password"
								id="password"
								class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
								placeholder="••••••••"
								bind:value={password}
								required
							/>
						</div>
						<div>
							<label
								for="verification"
								class="mb-2 block text-sm font-medium text-gray-900 dark:text-white"
								>Verification (2FA)</label
							>
							<select
								name="verification"
								id="verification"
								class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
								bind:value={verification}
								required
							>
								<option value="" selected>Select verification method</option>
								<option value="email">Email code</option>
								<option value="totp">TOTP code</option>
								<option value="passkey">Passkey</option>
								<option value="webauthn">WebAuthn</option>
							</select>
						</div>
						<div class="flex items-center justify-between">
							<div class="flex items-start">
								<div class="flex h-5 items-center">
									<input
										type="checkbox"
										name="remember"
										id="remember"
										value="true"
										aria-describedby="remember"
										class="focus:ring-3 focus:ring-primary-300 dark:focus:ring-primary-600 h-4 w-4 rounded border border-gray-300 bg-gray-50 dark:border-gray-600 dark:bg-gray-700 dark:ring-offset-gray-800"
										bind:checked={remember}
									/>
								</div>
								<div class="ml-3 text-sm">
									<label for="remember" class="text-gray-500 dark:text-gray-300">Remember me</label>
								</div>
							</div>
						</div>
						<button
							type="submit"
							class="bg-primary-600 hover:bg-primary-700 focus:ring-primary-300 dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 w-full rounded-lg px-5 py-2.5 text-center text-sm font-medium text-white focus:outline-none focus:ring-4"
							>Sign in</button
						>
					</form>
					<div class="flex items-center justify-between">
						<a
							class="button w-full rounded-lg bg-gray-600 px-5 py-2.5 text-center text-sm font-medium text-white hover:bg-gray-700 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:bg-gray-600 dark:hover:bg-gray-700 dark:focus:ring-gray-800"
							href="/">Cancel</a
						>
					</div>
				</div>
			</div>
		{/await}
	</div>
</section>
