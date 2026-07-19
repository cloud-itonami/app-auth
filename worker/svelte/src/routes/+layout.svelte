<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { theme, applyTheme } from '$lib/theme';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';

	let { children } = $props();

	onMount(() => {
		applyTheme($theme);
	});
</script>

<ThemeToggle />
{@render children()}
