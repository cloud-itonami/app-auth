import { writable } from 'svelte/store';
import { browser } from '$app/environment';

type Theme = 'dark' | 'light';

function getInitialTheme(): Theme {
	if (!browser) return 'dark';
	const stored = localStorage.getItem('etzhayyim-auth-theme');
	if (stored === 'light' || stored === 'dark') return stored;
	if (window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
	return 'dark';
}

export const theme = writable<Theme>(getInitialTheme());

/** Apply theme to <html> and persist. */
export function applyTheme(t: Theme): void {
	if (!browser) return;
	document.documentElement.setAttribute('data-theme', t);
	localStorage.setItem('etzhayyim-auth-theme', t);
}

/** Toggle between dark and light. */
export function toggleTheme(): void {
	theme.update((current) => {
		const next = current === 'dark' ? 'light' : 'dark';
		applyTheme(next);
		return next;
	});
}
