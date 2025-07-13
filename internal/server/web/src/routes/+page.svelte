<script lang="ts">
	import type { UserInfo } from '$lib/session';
	async function sessionUserInfo(): Promise<UserInfo> {
		const response = await fetch(`/session`);
		const userInfo: UserInfo = await response.json();
		return userInfo;
	}
</script>

<section class="bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white">
	<div class="mx-auto flex flex-col items-center justify-center px-6 py-8 md:h-screen lg:py-0">
	{#await sessionUserInfo() then userInfo}
		<p>Login: {userInfo.sub}</p>
	{:catch error}
		<a href="/" class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white">
			<img class="mr-2 h-64 w-64" src="/img/login.svg" alt="logo" />
		</a>
	{/await}
	</div>
</section>
