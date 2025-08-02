<script lang="ts">
	import Alert from '$lib/components/Alert.svelte';
	import type { UserInfo } from '$lib/session';
	import { CircleX, Cog, Fingerprint } from '@lucide/svelte';
	async function sessionUserInfo(): Promise<UserInfo> {
		const response = await fetch(`/session`);
		const userInfo: UserInfo = await response.json();
		return userInfo;
	}
</script>

<section class="bg-gray-50 dark:bg-gray-900">
	<div class="mx-auto flex flex-col items-center justify-center px-6 py-8 md:h-screen lg:py-0">
		<Alert />
		{#await sessionUserInfo() then userInfo}
			<div class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white">
				<Fingerprint />&nbsp;Welcome {userInfo.name}
			</div>
			<div
				class="w-full rounded-lg bg-white shadow sm:max-w-md md:mt-0 xl:p-0 dark:border dark:border-gray-700 dark:bg-gray-800"
			>
				<div class="space-y-4 p-6 sm:p-8 md:space-y-6">
					<h1
						class="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl dark:text-white"
					>
						Login
					</h1>
					<div class="space-y-4 md:space-y-6 text-gray-500 dark:text-gray-300">
						<p>Subject: {userInfo.subject}</p>
						<p>Email: {userInfo.email}</p>
						<p>TOTP:
							{#if userInfo.totp_registration}
							{new Date(userInfo.totp_registration).toDateString()}
							{:else}
							- <Cog size={16} /> <CircleX size={16} />
							{/if}
						</p>
					</div>
					<div class="flex items-center justify-between">
						<a
							class="button w-full rounded-lg bg-gray-600 px-5 py-2.5 text-center text-sm font-medium text-white hover:bg-gray-700 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:bg-gray-600 dark:hover:bg-gray-700 dark:focus:ring-gray-800"
							href="/session/terminate">Sign out</a
						>
					</div>
				</div>
			</div>
		{:catch}
			<a
				href="/user"
				class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white"
			>
				<Fingerprint size={96} />
			</a>
		{/await}
	</div>
</section>
