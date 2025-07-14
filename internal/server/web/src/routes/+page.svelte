<script lang="ts">
	import type { UserInfo } from '$lib/session';
	async function sessionUserInfo(): Promise<UserInfo> {
		const response = await fetch(`/session`);
		const userInfo: UserInfo = await response.json();
		return userInfo;
	}
</script>

<section class="bg-gray-50 dark:bg-gray-900">
	<div class="mx-auto flex flex-col items-center justify-center px-6 py-8 md:h-screen lg:py-0">
		{#await sessionUserInfo() then userInfo}
			<div class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white">
				<img class="mr-2 h-8 w-8" src="/img/login.svg" alt="logo" />
				Welcome {userInfo.given_name}
			</div>
			<div
				class="w-full rounded-lg bg-white shadow sm:max-w-md md:mt-0 xl:p-0 dark:border dark:border-gray-700 dark:bg-gray-800"
			>
				<div class="space-y-4 p-6 sm:p-8 md:space-y-6 text-gray-900 dark:text-white">
					<p>Subject: {userInfo.sub}</p>
					<p>Name: {userInfo.name}</p>
					<p>Email: {userInfo.email}</p>
					<p>Username: {userInfo.preferred_username}</p>
				</div>
			</div>
		{:catch}
			<a
				href="/user"
				class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white"
			>
				<img class="mr-2 h-64 w-64" src="/img/login.svg" alt="logo" />
			</a>
		{/await}
	</div>
</section>
