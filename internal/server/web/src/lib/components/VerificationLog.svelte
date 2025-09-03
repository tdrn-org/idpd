<script lang="ts">
	import { KNOWN_FLAGS } from '$lib/flags';
	import type { UserVerificationLog } from '$lib/session';

	export let id: string;
	export let log: UserVerificationLog;

	function formatDate(date: Date): string {
		const now = new Date();
		const delta = {
			year: now.getUTCFullYear() - date.getUTCFullYear(),
			month: now.getUTCMonth() - date.getUTCMonth(),
			day: now.getUTCDate() - date.getUTCDate(),
			hour: now.getUTCHours() - date.getUTCHours(),
			minute: now.getUTCMinutes() - date.getUTCMinutes(),
			second: now.getUTCSeconds() - date.getUTCSeconds()
		};
		if (delta.year > 0) {
			return date.toDateString();
		}
		if (delta.month > 1) {
			return delta.month + ' months ago';
		}
		if (delta.month > 0) {
			return delta.month + ' month ago';
		}
		if (delta.day > 1) {
			return delta.day + ' days ago';
		}
		if (delta.day > 0) {
			return delta.day + ' day ago';
		}
		if (delta.hour > 1) {
			return delta.hour + ' hours ago';
		}
		if (delta.hour > 0) {
			return delta.hour + ' hour ago';
		}
		if (delta.minute > 1) {
			return delta.minute + ' minutes ago';
		}
		if (delta.minute > 0) {
			return delta.minute + ' minute ago';
		}
		if (delta.second > 1) {
			return delta.second + ' seconds ago';
		}
		return '1 second ago';
	}
</script>

<div>
	Registration:
	{#if log.registration}
		{formatDate(new Date(log.registration))}
	{:else}
		-
	{/if}
</div>
<div>
	Last used:
	{#if log.last_used}
		{formatDate(new Date(log.last_used))}
		{#if log.country_code}
			(<button popovertarget="{id}">
				{#if log.city}
					{log.city},
				{/if}
				{#if KNOWN_FLAGS.has(log.country_code.toLowerCase())}
					<img
						src="img/flags/{log.country_code.toLowerCase()}.svg"
						alt="{log.country_code} country flag"
						width={24}
						height={16}
						class="inline"
					/>
				{:else}
					{log.country_code.toUpperCase()}
				{/if}
			</button>)
			<div
				id="{id}"
				popover
				class="space-y-2 p-4 shadow-xs rounded-lg border border-gray-200 bg-white text-sm text-gray-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-400"
			>
				<p>
					From: {log.host}
				</p>
				{#if log.city}
					City: {log.city}
				{/if}
				<p>
					Country: {log.country}
					<img
						src="img/flags/{log.country_code.toLowerCase()}.svg"
						alt="{log.country_code} country flag"
						width={24}
						height={16}
						class="inline"
					/>
				</p>
				<p>
					Location: <a href="https://maps.google.com/?q={log.lat},{log.lon}">{log.lat}, {log.lon}</a
					>
				</p>
			</div>
		{/if}
	{:else}
		-
	{/if}
</div>
