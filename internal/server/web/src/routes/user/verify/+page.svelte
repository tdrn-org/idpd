<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Fingerprint } from '@lucide/svelte';

	let id: string | null = '';
	let subject: string | null = '';
	let verification: string | null = '';
	let code: string = '';

	onMount(() => {
		id = page.url.searchParams.get('id');
		subject = page.url.searchParams.get('subject');
		verification = page.url.searchParams.get('verification');
		if (!id || !subject || !verification) {
			restartLogin();
		}
	});

	function restartLogin() {
		goto('/authenticate');
	}
</script>

<section class="bg-gray-50 dark:bg-gray-900">
	<div class="mx-auto flex flex-col items-center justify-center px-6 py-8 md:h-screen lg:py-0">
		<div class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white">
			<Fingerprint size={24} />&nbsp;Verify
		</div>
		<div
			class="w-full rounded-lg bg-white shadow sm:max-w-md md:mt-0 xl:p-0 dark:border dark:border-gray-700 dark:bg-gray-800"
		>
			<div class="space-y-4 p-6 sm:p-8 md:space-y-6">
				<h1
					class="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl dark:text-white"
				>
					Verify your login
				</h1>
				<form class="space-y-4 md:space-y-6" action="/session/verify" method="post">
					<input type="hidden" name="id" value={id} />
					<input type="hidden" name="verification" value={verification} />
					{#if verification == 'email'}
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
								class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-400 dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
								placeholder="Enter your login"
								bind:value={subject}
								required
								readonly
							/>
						</div>
						<div>
							<label for="code" class="mb-2 block text-sm font-medium text-gray-900 dark:text-white"
								>Code</label
							>
							<input
								type="input"
								name="response"
								id="response"
								class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
								placeholder="Enter the code you received via email"
								bind:value={code}
								required
							/>
						</div>
					{/if}
					<button
						type="submit"
						class="bg-primary-600 hover:bg-primary-700 focus:ring-primary-300 dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 w-full rounded-lg px-5 py-2.5 text-center text-sm font-medium text-white focus:outline-none focus:ring-4"
						>Verifiy</button
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
	</div>
</section>
