<script lang="ts">
	import ParticleCanvas from '$lib/components/ParticleCanvas.svelte';
	import YoroMascot from '$lib/components/YoroMascot.svelte';
	import { passkeyAuth, getOAuthParams, completeAuth } from '$lib/passkey';
	import { theme } from '$lib/theme';

	let status = $state('');
	let statusKind: 'error' | 'success' | '' = $state('');
	let loading = $state(false);
	let mascot: YoroMascot;
	let yoroError: '' | 'notFound' | 'authFailed' = $state('');

	const oauth = typeof window !== 'undefined' ? getOAuthParams() : null;

	async function doSignIn() {
		loading = true;
		status = 'Waiting for passkey...';
		statusKind = '';
		yoroError = '';
		try {
			if (!navigator.credentials) throw new Error('Passkey not supported');
			mascot?.speak('Confirm with your device...');
			const result = await passkeyAuth();
			status = 'Authenticated! Redirecting...';
			statusKind = 'success';
			await completeAuth(result.did, result.handle, oauth);
		} catch (e: any) {
			const msg = e?.message || 'Sign in failed';
			const isCancelled = /cancel/i.test(msg);
			const isNotFound = /no account|not found|sign up first/i.test(msg);
			const isAuthFailed = /authentication failed|verification failed/i.test(msg);
			const isNoPasskey =
				/not allowed/i.test(msg) ||
				/timed out/i.test(msg) ||
				/no passkey/i.test(msg);
			if (isCancelled) {
				status = '';
				statusKind = '';
			} else if (isNotFound) {
				status = '';
				statusKind = '';
				yoroError = 'notFound';
				mascot?.speak('アカウントが見つからないよ\u2026\u2026 新しく作ってね!');
			} else if (isNoPasskey) {
				status = 'etzhayyim.com の passkey がこのブラウザで見つからないか、選択されませんでした。';
				statusKind = 'error';
				mascot?.speak('このブラウザで使える passkey を選んでね。見つからないなら新規登録だよ。');
			} else if (isAuthFailed) {
				status = '';
				statusKind = '';
				yoroError = 'authFailed';
				mascot?.speak('認証に失敗しちゃった\u2026\u2026 もう一度試してね!');
			} else {
				status = msg;
				statusKind = 'error';
			}
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Sign In — etzhayyim</title>
</svelte:head>

<ParticleCanvas />

<div class="relative z-10 flex flex-col items-center justify-center min-h-screen p-5">
	<YoroMascot bind:this={mascot} />

	<div class="auth-card w-full max-w-[400px] backdrop-blur-[20px] border rounded-[20px] p-8 text-center animate-fade-up
		{$theme === 'dark'
			? 'bg-[rgba(26,26,26,0.95)] border-[#2a2a2a] shadow-[0_30px_90px_rgba(0,0,0,0.45)]'
			: 'bg-[rgba(255,255,255,0.92)] border-[#e0e0e0] shadow-[0_20px_60px_rgba(0,0,0,0.1)]'}">

		<h1 class="text-2xl font-bold mb-1 tracking-tight {$theme === 'dark' ? 'text-white' : 'text-gray-900'}">etzhayyim</h1>
		<p class="text-[13px] mb-5 {$theme === 'dark' ? 'text-[#888]' : 'text-gray-500'}">Sign In</p>

		<button
			onclick={doSignIn}
			disabled={loading}
			class="w-full py-[15px] border-none rounded-xl text-[16px] font-semibold cursor-pointer transition-all duration-200 bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] text-white shadow-[0_4px_16px_rgba(99,102,241,0.3)] hover:-translate-y-px hover:shadow-[0_6px_24px_rgba(99,102,241,0.4)] active:translate-y-0 active:shadow-[0_2px_8px_rgba(99,102,241,0.3)] disabled:bg-[#333] disabled:text-[#666] disabled:cursor-not-allowed disabled:shadow-none disabled:transform-none"
		>
			&#128274; Sign In with Passkey
		</button>
		<p class="text-[11px] mt-2.5 text-center {$theme === 'dark' ? 'text-[#555]' : 'text-gray-400'}">
			Use Touch ID, Face ID, or your saved passkey.
		</p>

		<div class="flex items-center gap-3 my-4 text-xs {$theme === 'dark' ? 'text-[#444]' : 'text-gray-300'}">
			<span class="flex-1 h-px {$theme === 'dark' ? 'bg-[#2a2a2a]' : 'bg-gray-200'}"></span>
			or
			<span class="flex-1 h-px {$theme === 'dark' ? 'bg-[#2a2a2a]' : 'bg-gray-200'}"></span>
		</div>

		<a
			href="/sign-up"
			class="text-[#818cf8] no-underline text-[13px] transition-colors hover:text-[#a5b4fc]"
		>
			Don't have an account? Sign up
		</a>

		{#if yoroError === 'notFound'}
			<div class="mt-4 p-4 rounded-xl border {$theme === 'dark' ? 'bg-[rgba(99,102,241,0.08)] border-[rgba(99,102,241,0.2)]' : 'bg-[rgba(99,102,241,0.05)] border-[rgba(99,102,241,0.15)]'}">
				<p class="text-[14px] mb-3 {$theme === 'dark' ? 'text-[#ccc]' : 'text-gray-700'}">
					アカウントが見つからないよ&#x2026;&#x2026;<br />新しく作ってね!
				</p>
				<a
					href="/sign-up"
					class="inline-block w-full py-3 text-center border-none rounded-xl text-[15px] font-semibold bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] text-white no-underline"
				>
					アカウントを作成する
				</a>
			</div>
		{:else if yoroError === 'authFailed'}
			<div class="mt-4 p-4 rounded-xl border {$theme === 'dark' ? 'bg-[rgba(248,113,113,0.08)] border-[rgba(248,113,113,0.2)]' : 'bg-[rgba(248,113,113,0.05)] border-[rgba(248,113,113,0.15)]'}">
				<p class="text-[14px] mb-3 {$theme === 'dark' ? 'text-[#ccc]' : 'text-gray-700'}">
					認証に失敗しちゃった&#x2026;&#x2026;<br />もう一度試すか、新しいアカウントを作ってね!
				</p>
				<div class="flex gap-2">
					<button
						onclick={doSignIn}
						class="flex-1 py-2.5 border rounded-xl text-[13px] font-semibold cursor-pointer {$theme === 'dark' ? 'border-[#444] text-[#ccc] bg-transparent hover:bg-[rgba(255,255,255,0.05)]' : 'border-gray-300 text-gray-700 bg-transparent hover:bg-gray-50'}"
					>
						もう一度試す
					</button>
					<a
						href="/sign-up"
						class="flex-1 py-2.5 text-center border-none rounded-xl text-[13px] font-semibold bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] text-white no-underline"
					>
						新規登録
					</a>
				</div>
			</div>
		{:else if status}
			<p
				class="mt-3 text-[13px] min-h-[20px] transition-all duration-300"
				class:text-[#888]={statusKind === ''}
				class:text-[#f87171]={statusKind === 'error'}
				class:text-[#4ade80]={statusKind === 'success'}
			>
				{status}
			</p>
		{/if}

		<div class="mt-3.5 text-[10px] leading-relaxed {$theme === 'dark' ? 'text-[#444]' : 'text-gray-400'}">
			By continuing, you agree to our
			<a href="https://yoro.etzhayyim.com/terms" target="_blank" class="text-[#6366f1] hover:text-[#a5b4fc]">Terms</a>,
			<a href="https://yoro.etzhayyim.com/privacy" target="_blank" class="text-[#6366f1] hover:text-[#a5b4fc]">Privacy</a>,
			<a href="https://yoro.etzhayyim.com/support/kyc-policy" target="_blank" class="text-[#6366f1] hover:text-[#a5b4fc]">KYC</a> &amp;
			<a href="https://yoro.etzhayyim.com/support/aml-policy" target="_blank" class="text-[#6366f1] hover:text-[#a5b4fc]">AML/CTF</a> policies.
		</div>
	</div>
</div>

<style>
	@keyframes fade-up {
		from { opacity: 0; transform: translateY(16px); }
		to { opacity: 1; transform: translateY(0); }
	}
	.animate-fade-up { animation: fade-up 0.5s ease 0.1s both; }
</style>
