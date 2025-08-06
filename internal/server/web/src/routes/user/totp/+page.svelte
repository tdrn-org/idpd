<script lang="ts">
	import { goto } from '$app/navigation';
	import type { UserTOTPRegistrationRequest } from '$lib/session';
	import { RectangleEllipsis } from '@lucide/svelte';

	let code: string = '';

	async function sessionTOTPRegistrationRequest(): Promise<UserTOTPRegistrationRequest> {
		const response = await fetch(`/session/totp_register`);
		const registrationRequest: UserTOTPRegistrationRequest = await response.json();
		return registrationRequest;
	}

	async function writeClipboardText(data: string): Promise<void> {
		return navigator.clipboard.writeText(data);
	}
</script>

<section class="bg-gray-50 dark:bg-gray-900">
	<div class="mx-auto flex flex-col items-center justify-center px-6 py-8 md:h-screen lg:py-0">
		<div class="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white">
			<RectangleEllipsis size={24} />&nbsp;Register your TOTP device
		</div>
		<div
			class="w-full rounded-lg bg-white shadow sm:max-w-md md:mt-0 xl:p-0 dark:border dark:border-gray-700 dark:bg-gray-800"
		>
			<div class="space-y-4 p-6 sm:p-8 md:space-y-6">
				<h3
					class="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl dark:text-white"
				>
					Scan QR code or copy OTP URL to register your device
				</h3>
				{#await sessionTOTPRegistrationRequest() then registrationRequest}
					<div class="flex items-center justify-center">
						<img
							src="data:image/png;base64,{registrationRequest.qr_code}"
							width="256"
							height="256"
							alt="QR code"
						/>
					</div>
					<button
						type="button"
						class="bg-primary-600 hover:bg-primary-700 focus:ring-primary-300 dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 w-full rounded-lg px-5 py-2.5 text-center text-sm font-medium text-white focus:outline-none focus:ring-4"
						on:click={() => writeClipboardText(registrationRequest.otp_url)}>Copy OTP URL</button
					>
				{:catch}
					{goto('/?alert=server_failure')}
				{/await}
				<h3
					class="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl dark:text-white"
				>
					Enter TOTP code to verify registration
				</h3>
				<form class="space-y-4 md:space-y-6" action="/session/totp_verify" method="post">
					<div>
						<label for="code" class="mb-2 block text-sm font-medium text-gray-900 dark:text-white"
							>Code</label
						>
						<input
							type="input"
							name="code"
							id="code"
							class="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
							placeholder="Enter the code shown on your device"
							bind:value={code}
							required
						/>
					</div>
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
