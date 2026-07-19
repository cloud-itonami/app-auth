<script lang="ts">
	import { onMount } from 'svelte';

	const PHRASES = [
		'Welcome! Let me help you get started.',
		'Your AI agents are waiting for you!',
		'Passkey is the safest way to sign in.',
		'etzhayyim.com - AI Agent-First Platform',
		'Ready to create something amazing?'
	];

	let speechText = $state('');
	let speechVisible = $state(false);
	let tapped = $state(false);
	let phraseIdx = 0;

	function showSpeech(text?: string) {
		speechText = text || PHRASES[phraseIdx++ % PHRASES.length];
		speechVisible = false;
		requestAnimationFrame(() => (speechVisible = true));
	}

	/** Expose showSpeech for parent components. */
	export function speak(text: string) {
		showSpeech(text);
	}

	function tapMascot() {
		tapped = true;
		setTimeout(() => (tapped = false), 400);
		showSpeech();
	}

	onMount(() => {
		setTimeout(() => showSpeech(PHRASES[0]), 600);

		/* Blink loop */
		function blink() {
			setTimeout(() => {
				document.querySelectorAll('.yoro-eye').forEach((e) => {
					(e as HTMLElement).style.opacity = '0';
				});
				setTimeout(() => {
					document.querySelectorAll('.yoro-eye').forEach((e) => {
						(e as HTMLElement).style.opacity = '1';
					});
				}, 150);
				blink();
			}, 3000 + Math.random() * 3000);
		}
		blink();
	});
</script>

<div class="flex flex-col items-center mb-4">
	<!-- Mascot -->
	<button
		class="cursor-pointer select-none"
		class:animate-bounce-tap={tapped}
		onclick={tapMascot}
		type="button"
		aria-label="YORO mascot"
	>
		<svg
			viewBox="0 0 200 240"
			width="120"
			height="132"
			class="animate-float drop-shadow-[0_8px_24px_rgba(88,204,2,0.25)] transition-transform hover:scale-105"
			role="img"
		>
			<ellipse cx="100" cy="232" rx="38" ry="7" fill="rgba(0,0,0,0.15)" />
			<ellipse cx="76" cy="214" rx="17" ry="8" fill="#46A302" />
			<ellipse cx="124" cy="214" rx="17" ry="8" fill="#46A302" />
			<ellipse cx="100" cy="165" rx="46" ry="40" fill="#58CC02" />
			<ellipse cx="100" cy="173" rx="26" ry="20" fill="#8EE000" />
			<path d="M 54 152 Q 30 158 32 178" stroke="#46A302" stroke-width="13" fill="none" stroke-linecap="round" class="animate-wave-l" />
			<circle cx="32" cy="179" r="8" fill="#46A302" class="animate-wave-l" />
			<path d="M 146 152 Q 170 158 168 178" stroke="#46A302" stroke-width="13" fill="none" stroke-linecap="round" class="animate-wave-r" />
			<circle cx="168" cy="179" r="8" fill="#46A302" class="animate-wave-r" />
			<circle cx="100" cy="102" r="48" fill="#58CC02" />
			<ellipse cx="78" cy="96" rx="17" ry="17" fill="white" />
			<ellipse cx="122" cy="96" rx="17" ry="17" fill="white" />
			<circle cx="80" cy="100" r="10" fill="#1CB0F6" class="yoro-eye" />
			<circle cx="124" cy="100" r="10" fill="#1CB0F6" class="yoro-eye" />
			<circle cx="80" cy="100" r="4.5" fill="#1A1A2E" class="yoro-eye" />
			<circle cx="124" cy="100" r="4.5" fill="#1A1A2E" class="yoro-eye" />
			<circle cx="85" cy="94" r="3.5" fill="white" class="yoro-eye" />
			<circle cx="129" cy="94" r="3.5" fill="white" class="yoro-eye" />
			<path d="M 73 116 Q 100 140 127 116" stroke="#1A1A1A" stroke-width="2.5" fill="white" stroke-linecap="round" />
			<line x1="88" y1="117" x2="88" y2="126" stroke="#1A1A1A" stroke-width="1.2" />
			<line x1="100" y1="118" x2="100" y2="128" stroke="#1A1A1A" stroke-width="1.2" />
			<line x1="112" y1="117" x2="112" y2="126" stroke="#1A1A1A" stroke-width="1.2" />
			<ellipse cx="58" cy="110" rx="9" ry="5.5" fill="#ff9999" opacity="0.3" />
			<ellipse cx="142" cy="110" rx="9" ry="5.5" fill="#ff9999" opacity="0.3" />
			<ellipse cx="100" cy="62" rx="36" ry="9" fill="#e0e0e0" />
			<rect x="72" y="42" width="56" height="22" rx="7" fill="#ececee" />
			<ellipse cx="100" cy="42" rx="26" ry="9" fill="#e0e0e0" />
			<rect x="82" y="32" width="36" height="13" rx="5" fill="#d8d8da" />
		</svg>
	</button>

	<!-- Speech bubble -->
	{#if speechText}
		<div
			class="relative bg-[#222] border border-[#333] rounded-xl px-4 py-2 text-[13px] text-[#ccc] mt-2 transition-all duration-300"
			class:opacity-0={!speechVisible}
			class:translate-y-2={!speechVisible}
			class:opacity-100={speechVisible}
			class:translate-y-0={speechVisible}
		>
			<div class="absolute -top-1.5 left-1/2 -translate-x-1/2 w-0 h-0 border-l-[6px] border-l-transparent border-r-[6px] border-r-transparent border-b-[6px] border-b-[#222]"></div>
			{speechText}
		</div>
	{/if}
</div>

<style>
	@keyframes float {
		0%, 100% { transform: translateY(0); }
		50% { transform: translateY(-8px); }
	}
	@keyframes wave-l {
		0%, 100% { transform: rotate(0deg); }
		25% { transform: rotate(-12deg); }
		75% { transform: rotate(8deg); }
	}
	@keyframes wave-r {
		0%, 100% { transform: rotate(0deg); }
		25% { transform: rotate(12deg); }
		75% { transform: rotate(-8deg); }
	}
	@keyframes bounce-tap {
		0% { transform: scale(1); }
		20% { transform: scale(0.88); }
		50% { transform: scale(1.1); }
		70% { transform: scale(0.96); }
		100% { transform: scale(1); }
	}
	.animate-float { animation: float 3s ease-in-out infinite; }
	.animate-wave-l { transform-origin: 54px 152px; animation: wave-l 4s ease-in-out infinite; }
	.animate-wave-r { transform-origin: 146px 152px; animation: wave-r 4s ease-in-out 2s infinite; }
	.animate-bounce-tap { animation: bounce-tap 0.4s ease-out; }
	@media (prefers-reduced-motion: reduce) {
		.animate-float, .animate-wave-l, .animate-wave-r { animation: none; }
	}
</style>
