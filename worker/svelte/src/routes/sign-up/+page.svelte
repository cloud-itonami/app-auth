<script lang="ts">
	import { onMount } from 'svelte';
	import ParticleCanvas from '$lib/components/ParticleCanvas.svelte';
	import YoroMascot from '$lib/components/YoroMascot.svelte';
	import { passkeyRegister, completeAuth, sendOtp, verifyOtp } from '$lib/passkey';
	import { theme } from '$lib/theme';

	type Step = 'signup' | 'membership' | 'phone' | 'telecom';

	let step: Step = $state('signup');
	let status = $state('');
	let statusKind: 'error' | 'success' | '' = $state('');
	let loading = $state(false);
	let mascot: YoroMascot;

	let authDid = $state('');
	let authHandle = $state('');

	let selectedPlan: 'free' | 'verified' | 'telecom' | '' = $state('');

	let phoneCC = $state('+81');
	let phoneNumber = $state('');
	let otpCode = $state('');
	let otpSent = $state(false);

	// Charter Rider §2 (ADR-2605192115): Telecom-tier provisioning is now
	// gated on a USDC donation (purpose='internal-subscription') instead
	// of Stripe Checkout. The Worker no longer issues SetupIntents.
	let donateAmount = $state('19.80'); // ≈ ¥2,980 at 1 USD = ¥150 ref rate; final amount set by treasury policy
	let donateTreasury = $state('0x0000000000000000000000000000000000000000');
	let donateTxHash = $state('');
	let donateSubmitting = $state(false);

	const API = typeof window !== 'undefined' ? location.origin : '';

	const COUNTRIES = [
		['JP', '+81', 'Japan'], ['US', '+1', 'United States'], ['GB', '+44', 'United Kingdom'],
		['KR', '+82', 'South Korea'], ['CN', '+86', 'China'], ['TW', '+886', 'Taiwan'],
		['HK', '+852', 'Hong Kong'], ['SG', '+65', 'Singapore'], ['AU', '+61', 'Australia'],
		['DE', '+49', 'Germany'], ['FR', '+33', 'France'], ['IT', '+39', 'Italy'],
		['ES', '+34', 'Spain'], ['NL', '+31', 'Netherlands'], ['SE', '+46', 'Sweden'],
		['CH', '+41', 'Switzerland'], ['IN', '+91', 'India'], ['ID', '+62', 'Indonesia'],
		['TH', '+66', 'Thailand'], ['VN', '+84', 'Vietnam'], ['PH', '+63', 'Philippines'],
		['CA', '+1', 'Canada'], ['MX', '+52', 'Mexico'], ['BR', '+55', 'Brazil'],
	] as const;

	function flag(iso: string): string {
		return String.fromCodePoint(...[...iso.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
	}

	let isDark = $derived($theme === 'dark');

	onMount(async () => {
		try {
			const cfg = await fetch(`${API}/xrpc/com.etzhayyim.auth.getConfig`).then((r) => r.json());
			// Charter Rider §2: stripe_pk is intentionally empty.
			// Treasury address comes from a (future) auth.getDonationConfig surface.
			donateTreasury = (cfg.donate_treasury_base_l2 as string) || donateTreasury;
		} catch { /* optional */ }
	});

	async function doSignUp() {
		loading = true;
		status = 'Waiting for passkey...';
		statusKind = '';
		try {
			if (!navigator.credentials) throw new Error('Passkey not supported on this browser');
			mascot?.speak('Confirm with your device...');
			const result = await passkeyRegister();
			authDid = result.did;
			authHandle = result.handle;
			mascot?.speak('Welcome! Choose your Membership plan.');
			status = 'Account created!';
			statusKind = 'success';
			step = 'membership';
		} catch (e: any) {
			status = e?.message || 'Passkey failed';
			statusKind = 'error';
		} finally {
			loading = false;
		}
	}

	function selectPlan(plan: 'free' | 'verified' | 'telecom') { selectedPlan = plan; }

	async function confirmPlan() {
		status = ''; statusKind = '';
		if (selectedPlan === 'free') { await completeAuth(authDid, authHandle); return; }
		if (selectedPlan === 'verified') { step = 'phone'; mascot?.speak('Verify your phone for full access!'); }
		else if (selectedPlan === 'telecom') { step = 'telecom'; mascot?.speak('Make a USDC donation to activate your eSIM!'); }
	}

	async function doPhoneVerify() {
		loading = true; status = ''; statusKind = '';
		try {
			const phone = phoneCC + phoneNumber.replace(/^0+/, '');
			if (!phone || phone.length < 8) throw new Error('Enter a valid phone number');
			if (!otpSent) {
				status = 'Sending verification code...';
				await sendOtp(phone);
				otpSent = true;
				mascot?.speak('Code sent! Check your phone.');
				status = 'Sent!'; statusKind = 'success';
			} else {
				if (!otpCode || otpCode.length !== 6) throw new Error('Enter 6-digit code');
				status = 'Verifying...';
				await verifyOtp(phone, otpCode);
				mascot?.speak('Phone verified!');
				await completeAuth(authDid, authHandle);
			}
		} catch (e: any) { status = e?.message || 'Failed'; statusKind = 'error'; }
		finally { loading = false; }
	}

	// Charter Rider §2 (ADR-2605192115): replaces the Stripe.js card flow.
	// User submits a USDC donation (internal-subscription purpose) on
	// Base L2; eSIM provisioning runs once the donation tx is confirmed.
	async function submitDonation() {
		donateSubmitting = true;
		status = 'Submitting USDC donation...';
		statusKind = '';
		donateTxHash = '';
		try {
			if (!donateTreasury || !/^0x[a-fA-F0-9]{40}$/.test(donateTreasury)) {
				throw new Error('Treasury address not configured. Contact support.');
			}
			if (!/^\d+(\.\d{1,6})?$/.test(donateAmount)) {
				throw new Error('Enter a valid USDC amount (e.g. 19.80).');
			}
			const r = await fetch(`${API}/api/donate`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					to: donateTreasury,
					amountUsdc: donateAmount,
					purpose: 'internal-subscription',
					memo: `auth Telecom membership: ${authDid}`,
				}),
			}).then((res) => res.json());
			if (r.error) throw new Error(r.message || r.error);
			donateTxHash = r.txHash ?? r.paymentReceipt?.txHash ?? '';
			status = 'Donation confirmed! Provisioning eSIM...';
			statusKind = 'success';
			const esim = await fetch(`${API}/xrpc/com.etzhayyim.auth.esimProvision`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: '{}',
			}).then((res) => res.json()).catch((error) => {
				console.warn('[silent-fail] sign-up/+page.svelte: esimProvision failed', error);
				return {};
			});
			if (esim.qr_code_url || esim.activation_url) mascot?.speak('Scan QR to install eSIM!');
			else mascot?.speak('Membership Telecom activated!');
			setTimeout(() => completeAuth(authDid, authHandle), 2000);
		} catch (e: any) {
			status = e?.message || 'Donation failed';
			statusKind = 'error';
		} finally {
			donateSubmitting = false;
		}
	}
</script>

<svelte:head>
	<title>Create Account — etzhayyim</title>
</svelte:head>

<ParticleCanvas />

<div class="relative z-10 flex flex-col items-center justify-center min-h-screen p-5">
	<YoroMascot bind:this={mascot} />

	<div class="auth-card w-full max-w-[400px] backdrop-blur-[20px] border rounded-[20px] p-8 text-center animate-fade-up
		{isDark
			? 'bg-[rgba(26,26,26,0.95)] border-[#2a2a2a] shadow-[0_30px_90px_rgba(0,0,0,0.45)]'
			: 'bg-[rgba(255,255,255,0.92)] border-[#e0e0e0] shadow-[0_20px_60px_rgba(0,0,0,0.1)]'}">

		<h1 class="text-2xl font-bold mb-1 tracking-tight {isDark ? 'text-white' : 'text-gray-900'}">etzhayyim</h1>
		<p class="text-[13px] mb-5 {isDark ? 'text-[#888]' : 'text-gray-500'}">Create Account</p>

		{#if step === 'signup'}
			<button onclick={doSignUp} disabled={loading}
				class="w-full py-[15px] border-none rounded-xl text-[16px] font-semibold cursor-pointer transition-all duration-200 bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] text-white shadow-[0_4px_16px_rgba(99,102,241,0.3)] hover:-translate-y-px active:translate-y-0 disabled:bg-[#ccc] disabled:text-[#888] disabled:cursor-not-allowed disabled:shadow-none disabled:transform-none">
				&#128274; Create Account
			</button>
			<p class="text-[11px] mt-2.5 {isDark ? 'text-[#555]' : 'text-gray-400'}">Uses Touch ID, Face ID, or device PIN. No password needed.</p>
		{/if}

		{#if step === 'membership'}
			<div class="text-left">
				<p class="text-[16px] font-bold mb-1 {isDark ? 'text-white' : 'text-gray-900'}">Membership</p>
				<p class="text-[12px] mb-4 {isDark ? 'text-[#888]' : 'text-gray-500'}">Choose your plan. Upgrade anytime.</p>
			</div>
			{#each [
				{ id: 'free', name: 'Free', sub: 'Guest', price: '¥0', desc: 'AI Agent と会話 · 制限付き投稿 · WiFi only', recommended: false },
				{ id: 'verified', name: 'Verified', sub: '', price: '¥0', desc: 'Phone 認証でフル機能 · 投稿無制限 · DM', recommended: false },
				{ id: 'telecom', name: 'Telecom', sub: '', price: '¥2,980/mo', desc: 'eSIM 3GB · 通話 · SMS · フル機能', recommended: true }
			] as plan (plan.id)}
				<button onclick={() => selectPlan(plan.id as any)}
					class="w-full text-left border rounded-[14px] p-4 mb-2.5 cursor-pointer transition-all duration-200 relative
						{selectedPlan === plan.id || plan.recommended ? 'border-[#6366f1]' : isDark ? 'border-[#333]' : 'border-gray-200'}
						{selectedPlan === plan.id ? 'bg-[rgba(99,102,241,0.12)] shadow-[0_0_0_2px_rgba(99,102,241,0.3)]' : isDark ? 'bg-[rgba(17,17,17,0.6)]' : 'bg-white/80'}">
					{#if plan.recommended}
						<span class="absolute -top-2 right-3 bg-[#6366f1] text-white text-[10px] font-bold px-2 py-0.5 rounded-lg">RECOMMENDED</span>
					{/if}
					<div class="flex justify-between items-center">
						<div>
							<span class="text-[15px] font-semibold {isDark ? 'text-white' : 'text-gray-900'}">{plan.name}</span>
							{#if plan.sub}<span class="text-[12px] ml-2 {isDark ? 'text-[#888]' : 'text-gray-400'}">{plan.sub}</span>{/if}
						</div>
						<span class="text-[15px] font-bold {plan.recommended ? 'text-[#818cf8]' : 'text-[#4ade80]'}">{plan.price}</span>
					</div>
					<p class="text-[12px] mt-1.5 {isDark ? 'text-[#777]' : 'text-gray-500'}">{plan.desc}</p>
				</button>
			{/each}
			<button onclick={confirmPlan} disabled={!selectedPlan}
				class="w-full mt-1 py-3.5 border-none rounded-xl text-[15px] font-semibold cursor-pointer bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] text-white disabled:bg-[#ccc] disabled:text-[#888] disabled:cursor-not-allowed">
				{selectedPlan === 'free' ? 'Start Free' : selectedPlan === 'verified' ? 'Verify Phone' : selectedPlan === 'telecom' ? 'Set Up Telecom (¥2,980/mo)' : 'Select a plan to continue'}
			</button>
		{/if}

		{#if step === 'phone'}
			<div class="text-left">
				<p class="text-[14px] font-semibold mb-1 {isDark ? 'text-white' : 'text-gray-900'}">Phone Verification</p>
				<p class="text-[11px] mb-3.5 {isDark ? 'text-[#666]' : 'text-gray-500'}">Verify your phone number to unlock full features.</p>
			</div>
			<p class="text-left text-[12px] font-medium mb-1 {isDark ? 'text-[#666]' : 'text-gray-500'}">PHONE NUMBER</p>
			<div class="flex gap-2 mb-2.5">
				<select bind:value={phoneCC} class="w-[120px] border rounded-[10px] px-3 py-3 text-[15px] outline-none {isDark ? 'bg-[rgba(17,17,17,0.8)] border-[#333] text-[#e5e5e5] focus:border-[#6366f1]' : 'bg-white border-gray-200 text-gray-800 focus:border-[#6366f1]'}">
					{#each COUNTRIES as [iso, code, _name]}
						<option value={code}>{flag(iso)} {code}</option>
					{/each}
				</select>
				<input bind:value={phoneNumber} type="tel" placeholder="90 1234 5678"
					class="flex-1 border rounded-[10px] px-3.5 py-3 text-[15px] outline-none {isDark ? 'bg-[rgba(17,17,17,0.8)] border-[#333] text-[#e5e5e5] focus:border-[#6366f1]' : 'bg-white border-gray-200 text-gray-800 focus:border-[#6366f1]'}" />
			</div>
			{#if otpSent}
				<p class="text-left text-[12px] font-medium mb-1 {isDark ? 'text-[#666]' : 'text-gray-500'}">VERIFICATION CODE</p>
				<input bind:value={otpCode} type="text" maxlength="6" placeholder="000000" inputmode="numeric"
					class="w-full border rounded-[10px] px-3.5 py-3 text-[24px] outline-none tracking-[8px] text-center font-mono mb-2.5 {isDark ? 'bg-[rgba(17,17,17,0.8)] border-[#333] text-[#e5e5e5] focus:border-[#6366f1]' : 'bg-white border-gray-200 text-gray-800 focus:border-[#6366f1]'}" />
			{/if}
			<button onclick={doPhoneVerify} disabled={loading}
				class="w-full py-3.5 border-none rounded-xl text-[15px] font-semibold cursor-pointer bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] text-white disabled:bg-[#ccc] disabled:text-[#888] disabled:cursor-not-allowed">
				{otpSent ? 'Verify Code' : 'Send Code'}
			</button>
		{/if}

		{#if step === 'telecom'}
			<div class="text-left">
				<p class="text-[14px] font-semibold mb-1 {isDark ? 'text-white' : 'text-gray-900'}">USDC donation &amp; eSIM</p>
				<p class="text-[11px] mb-3.5 {isDark ? 'text-[#666]' : 'text-gray-500'}">
					Membership Telecom is funded by a USDC donation on Base L2
					(purpose=<code>internal-subscription</code>) per
					<a class="underline" href="https://github.com/etzhayyim/root/blob/main/CHARTER-RIDER.md" target="_blank" rel="noreferrer">Charter Rider §2</a>.
				</p>
			</div>
			<label class="text-[12px] {isDark ? 'text-[#888]' : 'text-gray-500'}">
				Amount (USDC)
				<input bind:value={donateAmount} type="text" inputmode="decimal"
					class="mt-1 w-full border rounded-[10px] px-3.5 py-3 text-[15px] outline-none {isDark ? 'bg-[rgba(17,17,17,0.8)] border-[#333] text-[#e5e5e5] focus:border-[#6366f1]' : 'bg-white border-gray-200 text-gray-800 focus:border-[#6366f1]'}" />
			</label>
			<label class="text-[12px] {isDark ? 'text-[#888]' : 'text-gray-500'} mt-3 block">
				Treasury address (Base L2)
				<input bind:value={donateTreasury} type="text"
					class="mt-1 w-full border rounded-[10px] px-3.5 py-3 text-[13px] font-mono outline-none {isDark ? 'bg-[rgba(17,17,17,0.8)] border-[#333] text-[#e5e5e5] focus:border-[#6366f1]' : 'bg-white border-gray-200 text-gray-800 focus:border-[#6366f1]'}" />
			</label>
			<button onclick={submitDonation} disabled={donateSubmitting}
				class="w-full mt-3 py-3.5 border-none rounded-xl text-[15px] font-semibold cursor-pointer bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] text-white disabled:bg-[#ccc] disabled:text-[#888] disabled:cursor-not-allowed">
				{donateSubmitting ? 'Submitting…' : 'Submit USDC Donation &amp; Get eSIM'}
			</button>
			{#if donateTxHash}
				<p class="text-[11px] mt-2 {isDark ? 'text-[#666]' : 'text-gray-500'}">Tx: <code class="font-mono">{donateTxHash}</code></p>
			{/if}
		{/if}

		<div class="flex items-center gap-3 my-4 text-xs {isDark ? 'text-[#444]' : 'text-gray-300'}">
			<span class="flex-1 h-px {isDark ? 'bg-[#2a2a2a]' : 'bg-gray-200'}"></span>
			or
			<span class="flex-1 h-px {isDark ? 'bg-[#2a2a2a]' : 'bg-gray-200'}"></span>
		</div>

		<a href="/sign-in" class="text-[#818cf8] no-underline text-[13px] transition-colors hover:text-[#a5b4fc]">
			Already have an account? Sign in
		</a>

		{#if status}
			<p class="mt-3 text-[13px] min-h-[20px] transition-all duration-300"
				class:text-[#888]={statusKind === ''}
				class:text-[#f87171]={statusKind === 'error'}
				class:text-[#4ade80]={statusKind === 'success'}>
				{status}
			</p>
		{/if}

		<div class="mt-3.5 text-[10px] leading-relaxed {isDark ? 'text-[#444]' : 'text-gray-400'}">
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
