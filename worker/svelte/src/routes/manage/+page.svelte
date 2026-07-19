<script lang="ts">
  import { onMount } from 'svelte';
  import ParticleCanvas from '$lib/components/ParticleCanvas.svelte';
  import { theme } from '$lib/theme';

  type LinkedMethod = {
    provider: string;
    providerSubject: string;
    displayLabel: string;
    verified: boolean;
  };

  type SessionPayload = {
    ok: boolean;
    accountDid: string;
    activeDid: string;
    handle: string;
    linkedMethods: LinkedMethod[];
    actorScore: {
      score: number;
      verifiedMethodCount: number;
    };
  };

  type OrgSummary = {
    orgDid: string;
    role: string;
    name: string;
    domain: string | null;
    orgType: string;
  };

  type OrgMember = {
    memberDid: string;
    role: string;
    invitedBy: string | null;
    joinedAt: string;
    status: string;
  };

  // T4 topology: authz.etzhayyim.com owns linked methods + session state.
  // accounts.etzhayyim.com is served by the same authz Worker — location.origin works for both.
  const API = typeof window !== 'undefined' ? location.origin : '';

  let loading = $state(true);
  let error = $state('');
  let session = $state<SessionPayload | null>(null);

  let email = $state('');
  let emailCode = $state('');
  let emailPending = $state(false);
  let emailStatus = $state('');
  let linkStatus = $state('');

  // ── Persona (activeDid) switcher ────────────────────────────────────────
  let personaRequest = $state('');
  let personaStatus = $state('');

  // ── Org management ──────────────────────────────────────────────────────
  let orgs = $state<OrgSummary[]>([]);
  let orgsLoading = $state(false);
  let orgStatus = $state('');
  let selectedOrgDid = $state('');
  let selectedMembers = $state<OrgMember[]>([]);
  let newOrgName = $state('');
  let newOrgDomain = $state('');
  let newOrgType = $state<'personal' | 'company' | 'npo' | 'community' | 'team'>('personal');
  let inviteEmail = $state('');
  let inviteRole = $state<'member' | 'admin'>('member');
  let acceptToken = $state('');
  let editOrgName = $state('');
  let editOrgDomain = $state('');
  let editOrgType = $state<'personal' | 'company' | 'npo' | 'community' | 'team'>('personal');

  let isDark = $derived($theme === 'dark');

  async function loadSession() {
    loading = true;
    error = '';
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.getSession`, { credentials: 'include' });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to load account');
      session = body;
    } catch (e: any) {
      error = e?.message || 'Failed to load account';
      session = null;
    } finally {
      loading = false;
    }
  }

  async function beginEmailLink() {
    linkStatus = '';
    emailStatus = '';
    const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.linkEmailBegin`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.message || body.error || 'Failed to start email verification');
    emailPending = true;
    emailStatus = body.debugCode
      ? `Verification code issued. Dev code: ${body.debugCode}`
      : 'Verification code sent.';
  }

  async function verifyEmailLink() {
    linkStatus = '';
    emailStatus = '';
    const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.linkEmailVerify`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code: emailCode }),
    });
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.message || body.error || 'Failed to verify email');
    emailPending = false;
    emailCode = '';
    emailStatus = 'Email linked.';
    await loadSession();
  }

  async function startOAuth(provider: 'google' | 'microsoft') {
    const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.linkOAuthStart`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider }),
    });
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.message || body.error || `Failed to start ${provider} linking`);
    location.href = body.authorizationUrl;
  }

  async function unlinkMethod(method: LinkedMethod) {
    linkStatus = '';
    const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.unlinkMethod`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: method.provider, providerSubject: method.providerSubject }),
    });
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.message || body.error || 'Failed to unlink method');
    await loadSession();
  }

  async function handleOAuth(provider: 'google' | 'microsoft') {
    try {
      await startOAuth(provider);
    } catch (e: any) {
      linkStatus = e?.message || `Failed to start ${provider} linking`;
    }
  }

  async function handleUnlink(method: LinkedMethod) {
    try {
      await unlinkMethod(method);
    } catch (e: any) {
      linkStatus = e?.message || 'Failed to unlink method';
    }
  }

  async function handleEmailAction() {
    try {
      if (emailPending) {
        await verifyEmailLink();
      } else {
        await beginEmailLink();
      }
    } catch (e: any) {
      emailStatus = e?.message || 'Email verification failed';
    }
  }

  // ── Persona switch ─────────────────────────────────────────────────────
  async function switchActiveDid(targetDid: string) {
    personaStatus = '';
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.switchActiveDid`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ activeDid: targetDid }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to switch persona');
      personaStatus = `Switched to ${body.activeDid}`;
      await loadSession();
    } catch (e: any) {
      personaStatus = e?.message || 'Failed to switch persona';
    }
  }

  function defaultPersonaOptions(): { label: string; did: string }[] {
    if (!session) return [];
    const { accountDid } = session;
    return [
      { label: 'Organization persona', did: accountDid },
      { label: 'Default person', did: `${accountDid}:person:default` },
    ];
  }

  // ── Orgs ───────────────────────────────────────────────────────────────
  async function loadOrgs() {
    orgsLoading = true;
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgList`, { credentials: 'include' });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to load orgs');
      orgs = body.orgs || [];
      if (!selectedOrgDid && orgs.length > 0) selectedOrgDid = orgs[0].orgDid;
      if (selectedOrgDid) await loadOrgMembers(selectedOrgDid);
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to load orgs';
    } finally {
      orgsLoading = false;
    }
  }

  async function loadOrgMembers(orgDid: string) {
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgMembers?orgDid=${encodeURIComponent(orgDid)}`, {
        credentials: 'include',
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to load members');
      selectedMembers = body.members || [];
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to load members';
      selectedMembers = [];
    }
  }

  async function selectOrg(orgDid: string) {
    selectedOrgDid = orgDid;
    orgStatus = '';
    const found = orgs.find((o) => o.orgDid === orgDid);
    editOrgName = found?.name || '';
    editOrgDomain = found?.domain || '';
    editOrgType = (found?.orgType as typeof editOrgType) || 'personal';
    await loadOrgMembers(orgDid);
  }

  async function updateOrg() {
    orgStatus = '';
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgUpdate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          orgDid: selectedOrgDid,
          name: editOrgName || undefined,
          domain: editOrgDomain || undefined,
          orgType: editOrgType,
        }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to update org');
      orgStatus = 'Org updated';
      await loadOrgs();
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to update org';
    }
  }

  async function createOrg() {
    orgStatus = '';
    if (!newOrgName || newOrgName.length < 2) {
      orgStatus = 'Name must be at least 2 characters';
      return;
    }
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgCreate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newOrgName, domain: newOrgDomain || undefined, orgType: newOrgType }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to create org');
      orgStatus = `Created org ${body.orgDid}`;
      newOrgName = '';
      newOrgDomain = '';
      await loadOrgs();
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to create org';
    }
  }

  async function sendOrgInvite() {
    orgStatus = '';
    if (!selectedOrgDid) {
      orgStatus = 'Select an org first';
      return;
    }
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgInvite`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orgDid: selectedOrgDid, email: inviteEmail, role: inviteRole }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to invite');
      const sent = body.sent ? 'Invite email sent' : 'Invite created (email delivery unavailable)';
      const tokenHint = body.debugToken ? ` (dev token: ${body.debugToken.slice(0, 24)}…)` : '';
      orgStatus = `${sent} to ${inviteEmail}${tokenHint}`;
      inviteEmail = '';
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to invite';
    }
  }

  async function acceptInvite() {
    orgStatus = '';
    const token = acceptToken.trim();
    if (!token) {
      orgStatus = 'Paste the invite token first';
      return;
    }
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgInviteAccept`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to accept invite');
      orgStatus = `Joined ${body.orgDid} as ${body.role}`;
      acceptToken = '';
      await loadOrgs();
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to accept invite';
    }
  }

  async function updateMemberRole(memberDid: string, role: 'member' | 'admin') {
    orgStatus = '';
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgMemberRoleUpdate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orgDid: selectedOrgDid, memberDid, role }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to update role');
      orgStatus = `Updated role of ${memberDid} to ${role}`;
      await loadOrgMembers(selectedOrgDid);
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to update role';
    }
  }

  async function removeMember(memberDid: string) {
    orgStatus = '';
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgMemberRemove`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orgDid: selectedOrgDid, memberDid }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to remove member');
      orgStatus = `Removed ${memberDid}`;
      await loadOrgMembers(selectedOrgDid);
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to remove member';
    }
  }

  async function transferOwnership(newOwnerDid: string) {
    orgStatus = '';
    if (!confirm(`Transfer ownership of ${selectedOrgDid} to ${newOwnerDid}? You will become admin.`)) return;
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgTransferOwnership`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orgDid: selectedOrgDid, newOwnerDid }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to transfer ownership');
      orgStatus = `Ownership transferred to ${newOwnerDid}`;
      await Promise.all([loadOrgs(), loadOrgMembers(selectedOrgDid)]);
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to transfer ownership';
    }
  }

  async function leaveOrg(orgDid: string) {
    orgStatus = '';
    if (!confirm(`Leave ${orgDid}?`)) return;
    try {
      const resp = await fetch(`${API}/xrpc/com.etzhayyim.authz.orgLeave`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orgDid }),
      });
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.message || body.error || 'Failed to leave org');
      orgStatus = `Left ${orgDid}`;
      selectedOrgDid = '';
      selectedMembers = [];
      await loadOrgs();
    } catch (e: any) {
      orgStatus = e?.message || 'Failed to leave org';
    }
  }

  function callerRoleFor(orgDid: string): string {
    return orgs.find((o) => o.orgDid === orgDid)?.role || 'member';
  }

  onMount(async () => {
    await loadSession();
    if (session) await loadOrgs();
    const params = new URLSearchParams(location.search);
    const linkedResult = params.get('linked');
    if (linkedResult) {
      emailStatus = `${linkedResult} account linked.`;
    }
    const inviteParam = params.get('invite');
    if (inviteParam) {
      acceptToken = inviteParam;
      orgStatus = 'Invite token loaded. Click "Accept Invite" to join.';
    }
    if (linkedResult || inviteParam) history.replaceState(null, '', '/manage');
  });
</script>

<svelte:head>
  <title>Accounts — etzhayyim</title>
</svelte:head>

<ParticleCanvas />

<div class="relative z-10 min-h-screen px-5 py-10">
  <div class="mx-auto w-full max-w-5xl">
    <div class="mb-8 flex items-end justify-between gap-4">
      <div>
        <p class="mb-2 text-xs uppercase tracking-[0.28em] {isDark ? 'text-[#6b7280]' : 'text-gray-500'}">Accounts</p>
        <h1 class="m-0 text-4xl font-black tracking-tight {isDark ? 'text-white' : 'text-gray-900'}">Authentication Management</h1>
        <p class="mt-3 text-sm {isDark ? 'text-[#9ca3af]' : 'text-gray-600'}">`auth.etzhayyim.com` signs you in. `accounts.etzhayyim.com` manages linked authentication methods.</p>
      </div>
      <a
        href="https://auth.etzhayyim.com/sign-in?redirectUrl=https%3A%2F%2Faccounts.etzhayyim.com%2Fmanage"
        class="rounded-2xl px-4 py-3 text-sm font-semibold no-underline {isDark ? 'bg-white text-black' : 'bg-gray-900 text-white'}"
      >
        Sign In
      </a>
    </div>

    {#if loading}
      <div class="rounded-[28px] border p-8 {isDark ? 'border-[#1f2937] bg-[rgba(10,16,24,0.9)] text-[#9ca3af]' : 'border-gray-200 bg-white text-gray-600'}">
        Loading account...
      </div>
    {:else if error}
      <div class="rounded-[28px] border p-8 {isDark ? 'border-[#3f1d1d] bg-[rgba(32,10,10,0.9)]' : 'border-red-200 bg-red-50'}">
        <p class="m-0 text-base font-semibold {isDark ? 'text-[#fecaca]' : 'text-red-700'}">{error}</p>
        <p class="mt-2 mb-0 text-sm {isDark ? 'text-[#fca5a5]' : 'text-red-600'}">Sign in via `auth.etzhayyim.com` and return here.</p>
      </div>
    {:else if session}
      <div class="grid gap-6 md:grid-cols-[1.15fr,0.85fr]">
        <section class="rounded-[30px] border p-7 {isDark ? 'border-[#1f2937] bg-[rgba(6,10,18,0.92)]' : 'border-gray-200 bg-white'}">
          <div class="mb-6 flex items-start justify-between gap-4">
            <div>
              <p class="m-0 text-xs uppercase tracking-[0.24em] {isDark ? 'text-[#6b7280]' : 'text-gray-500'}">Actor</p>
              <h2 class="mt-2 mb-1 text-2xl font-bold {isDark ? 'text-white' : 'text-gray-900'}">{session.handle}</h2>
              <p class="m-0 break-all text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">{session.accountDid}</p>
            </div>
            <div class="rounded-[24px] px-5 py-4 text-center {isDark ? 'bg-[rgba(34,197,94,0.12)] text-[#86efac]' : 'bg-green-50 text-green-700'}">
              <div class="text-[11px] uppercase tracking-[0.2em]">Actor Score</div>
              <div class="mt-1 text-4xl font-black">{session.actorScore.score}</div>
            </div>
          </div>

          <div class="mb-5 rounded-[24px] p-5 {isDark ? 'bg-[rgba(15,23,42,0.85)]' : 'bg-slate-50'}">
            <div class="mb-3 flex items-center justify-between">
              <h3 class="m-0 text-lg font-semibold {isDark ? 'text-white' : 'text-gray-900'}">Linked Methods</h3>
              <span class="text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">{session.actorScore.verifiedMethodCount} verified methods</span>
            </div>
            <div class="space-y-3">
              {#each session.linkedMethods as method}
                <div class="flex items-center justify-between rounded-2xl border px-4 py-3 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-white'}">
                  <div>
                    <div class="text-sm font-semibold {isDark ? 'text-white' : 'text-gray-900'}">{method.provider}</div>
                    <div class="text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">{method.displayLabel}</div>
                  </div>
                  <div class="flex items-center gap-3">
                    <span class="rounded-full px-3 py-1 text-[11px] font-semibold {method.verified ? (isDark ? 'bg-[rgba(34,197,94,0.18)] text-[#86efac]' : 'bg-green-100 text-green-700') : (isDark ? 'bg-[rgba(245,158,11,0.18)] text-[#fcd34d]' : 'bg-amber-100 text-amber-700')}">
                      {method.verified ? 'verified' : 'pending'}
                    </span>
                    {#if method.provider !== 'passkey'}
                      <button
                        class="rounded-xl border px-3 py-2 text-xs font-semibold {isDark ? 'border-[#334155] text-[#cbd5e1]' : 'border-gray-300 text-gray-700'}"
                        onclick={() => handleUnlink(method)}
                      >
                        Remove
                      </button>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>
          </div>

          <div class="rounded-[24px] p-5 {isDark ? 'bg-[rgba(15,23,42,0.85)]' : 'bg-slate-50'}">
            <h3 class="m-0 text-lg font-semibold {isDark ? 'text-white' : 'text-gray-900'}">Score Rule</h3>
            <p class="mt-2 mb-0 text-sm leading-6 {isDark ? 'text-[#94a3b8]' : 'text-gray-600'}">
              Verified authentication methods are counted directly toward `actor.score`. Each verified method contributes `25` points. Passkey is always the base method; adding `email`, `Gmail`, and `Microsoft` can raise the score to `100`.
            </p>
          </div>
        </section>

        <section class="rounded-[30px] border p-7 {isDark ? 'border-[#1f2937] bg-[rgba(6,10,18,0.92)]' : 'border-gray-200 bg-white'}">
          <h2 class="mt-0 mb-5 text-2xl font-bold {isDark ? 'text-white' : 'text-gray-900'}">Add Authentication</h2>

          <div class="mb-6 rounded-[24px] border p-5 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-slate-50'}">
            <div class="mb-3">
              <div class="text-sm font-semibold {isDark ? 'text-white' : 'text-gray-900'}">Email</div>
              <div class="mt-1 text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Add an email-based recovery and authentication channel.</div>
            </div>
            <input
              bind:value={email}
              type="email"
              placeholder="you@example.com"
              class="mb-3 w-full rounded-2xl border px-4 py-3 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
            />
            {#if emailPending}
              <input
                bind:value={emailCode}
                type="text"
                placeholder="Verification code"
                class="mb-3 w-full rounded-2xl border px-4 py-3 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
              />
            {/if}
            <button
              class="w-full rounded-2xl border-none px-4 py-3 text-sm font-semibold text-white {isDark ? 'bg-[#2563eb]' : 'bg-blue-600'}"
              onclick={handleEmailAction}
            >
              {emailPending ? 'Verify Email' : 'Send Verification Code'}
            </button>
            {#if emailStatus}
              <p class="mb-0 mt-3 text-xs {isDark ? 'text-[#93c5fd]' : 'text-blue-700'}">{emailStatus}</p>
            {/if}
          </div>

          <div class="space-y-4">
            <button
              class="flex w-full items-center justify-between rounded-[24px] border px-5 py-4 text-left {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)] text-white' : 'border-gray-200 bg-slate-50 text-gray-900'}"
              onclick={() => handleOAuth('google')}
            >
              <span>
                <span class="block text-sm font-semibold">Gmail / Google</span>
                <span class="mt-1 block text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Link a Google identity as an additional sign-in method.</span>
              </span>
              <span class="text-xs font-semibold {isDark ? 'text-[#86efac]' : 'text-green-700'}">+25</span>
            </button>

            <button
              class="flex w-full items-center justify-between rounded-[24px] border px-5 py-4 text-left {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)] text-white' : 'border-gray-200 bg-slate-50 text-gray-900'}"
              onclick={() => handleOAuth('microsoft')}
            >
              <span>
                <span class="block text-sm font-semibold">Microsoft</span>
                <span class="mt-1 block text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Link Microsoft Entra / Outlook / Microsoft account access.</span>
              </span>
              <span class="text-xs font-semibold {isDark ? 'text-[#86efac]' : 'text-green-700'}">+25</span>
            </button>
          </div>
          {#if linkStatus}
            <p class="mb-0 mt-4 text-xs {isDark ? 'text-[#fca5a5]' : 'text-red-600'}">{linkStatus}</p>
          {/if}
        </section>
      </div>

      <!-- ── Persona (activeDid) switcher ─────────────────────────────────── -->
      <section class="mt-6 rounded-[30px] border p-7 {isDark ? 'border-[#1f2937] bg-[rgba(6,10,18,0.92)]' : 'border-gray-200 bg-white'}">
        <div class="mb-5 flex items-start justify-between gap-4">
          <div>
            <h2 class="m-0 text-2xl font-bold {isDark ? 'text-white' : 'text-gray-900'}">Persona</h2>
            <p class="mt-2 mb-0 text-sm {isDark ? 'text-[#94a3b8]' : 'text-gray-600'}">Switch the current `activeDid` (sub-actor). Custom paths must start with your accountDid.</p>
          </div>
          <div class="rounded-2xl border px-4 py-3 text-xs {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)] text-[#cbd5e1]' : 'border-gray-200 bg-slate-50 text-gray-700'}">
            <div class="mb-1 uppercase tracking-[0.2em] {isDark ? 'text-[#6b7280]' : 'text-gray-500'}">Active</div>
            <div class="break-all font-mono">{session.activeDid}</div>
          </div>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          {#each defaultPersonaOptions() as opt}
            <button
              class="rounded-2xl border px-4 py-3 text-left text-sm {session.activeDid === opt.did ? (isDark ? 'border-[#2563eb] bg-[rgba(37,99,235,0.15)] text-white' : 'border-blue-500 bg-blue-50 text-gray-900') : (isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)] text-white' : 'border-gray-200 bg-slate-50 text-gray-900')}"
              onclick={() => switchActiveDid(opt.did)}
              disabled={session.activeDid === opt.did}
            >
              <div class="text-sm font-semibold">{opt.label}</div>
              <div class="mt-1 break-all text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">{opt.did}</div>
            </button>
          {/each}
        </div>
        <div class="mt-4 flex flex-col gap-2 sm:flex-row">
          <input
            bind:value={personaRequest}
            placeholder="{session.accountDid}:team:engineering"
            class="flex-1 rounded-2xl border px-4 py-3 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
          />
          <button
            class="rounded-2xl border-none px-4 py-3 text-sm font-semibold text-white {isDark ? 'bg-[#2563eb]' : 'bg-blue-600'}"
            onclick={() => switchActiveDid(personaRequest.trim())}
            disabled={!personaRequest.trim()}
          >
            Switch
          </button>
        </div>
        {#if personaStatus}
          <p class="mb-0 mt-3 text-xs {isDark ? 'text-[#93c5fd]' : 'text-blue-700'}">{personaStatus}</p>
        {/if}
      </section>

      <!-- ── Orgs ────────────────────────────────────────────────────────── -->
      <section class="mt-6 rounded-[30px] border p-7 {isDark ? 'border-[#1f2937] bg-[rgba(6,10,18,0.92)]' : 'border-gray-200 bg-white'}">
        <div class="mb-5 flex items-end justify-between gap-4">
          <div>
            <h2 class="m-0 text-2xl font-bold {isDark ? 'text-white' : 'text-gray-900'}">Organizations</h2>
            <p class="mt-2 mb-0 text-sm {isDark ? 'text-[#94a3b8]' : 'text-gray-600'}">An account is also its own personal org. You can upgrade it or be invited to others.</p>
          </div>
          {#if orgsLoading}
            <span class="text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Loading...</span>
          {/if}
        </div>

        <div class="grid gap-6 md:grid-cols-[1fr,1.4fr]">
          <!-- ── Org list + create ── -->
          <div class="space-y-3">
            <div class="rounded-[24px] border p-4 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-slate-50'}">
              <div class="mb-3 text-xs font-semibold uppercase tracking-[0.2em] {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">My Orgs</div>
              {#if orgs.length === 0 && !orgsLoading}
                <p class="m-0 text-sm {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">No orgs yet. Create one below or accept an invite.</p>
              {:else}
                <ul class="m-0 list-none space-y-2 p-0">
                  {#each orgs as org}
                    <li class="rounded-2xl border p-3 {selectedOrgDid === org.orgDid ? (isDark ? 'border-[#2563eb] bg-[rgba(37,99,235,0.15)]' : 'border-blue-500 bg-blue-50') : (isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-white')}">
                      <div class="flex items-start justify-between gap-2">
                        <div class="flex-1 min-w-0">
                          <div class="text-sm font-semibold {isDark ? 'text-white' : 'text-gray-900'}">{org.name || org.orgDid}</div>
                          <div class="mt-1 break-all text-xs {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">{org.orgDid}</div>
                          <div class="mt-1 text-[11px] {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">role: {org.role} · type: {org.orgType}{org.domain ? ` · ${org.domain}` : ''}</div>
                        </div>
                        <div class="flex flex-col gap-1">
                          <button class="rounded-xl border px-2 py-1 text-[11px] font-semibold {isDark ? 'border-[#334155] text-[#cbd5e1]' : 'border-gray-300 text-gray-700'}" onclick={() => selectOrg(org.orgDid)}>View</button>
                          {#if org.role !== 'owner'}
                            <button class="rounded-xl border px-2 py-1 text-[11px] font-semibold {isDark ? 'border-[#3f1d1d] text-[#fca5a5]' : 'border-red-200 text-red-600'}" onclick={() => leaveOrg(org.orgDid)}>Leave</button>
                          {/if}
                        </div>
                      </div>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>

            <div class="rounded-[24px] border p-4 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-slate-50'}">
              <div class="mb-3 text-xs font-semibold uppercase tracking-[0.2em] {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Upgrade this account to an org</div>
              <input
                bind:value={newOrgName}
                placeholder="Org name"
                class="mb-2 w-full rounded-2xl border px-4 py-2 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
              />
              <input
                bind:value={newOrgDomain}
                placeholder="domain (optional)"
                class="mb-2 w-full rounded-2xl border px-4 py-2 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
              />
              <select
                bind:value={newOrgType}
                class="mb-2 w-full rounded-2xl border px-4 py-2 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
              >
                <option value="personal">personal</option>
                <option value="company">company</option>
                <option value="npo">npo</option>
                <option value="community">community</option>
                <option value="team">team</option>
              </select>
              <button
                class="w-full rounded-2xl border-none px-4 py-2 text-sm font-semibold text-white {isDark ? 'bg-[#2563eb]' : 'bg-blue-600'}"
                onclick={createOrg}
              >
                Create / Upgrade
              </button>
            </div>

            <div class="rounded-[24px] border p-4 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-slate-50'}">
              <div class="mb-3 text-xs font-semibold uppercase tracking-[0.2em] {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Accept invite</div>
              <input
                bind:value={acceptToken}
                placeholder="Paste invite token"
                class="mb-2 w-full rounded-2xl border px-4 py-2 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
              />
              <button
                class="w-full rounded-2xl border-none px-4 py-2 text-sm font-semibold text-white {isDark ? 'bg-[#16a34a]' : 'bg-green-600'}"
                onclick={acceptInvite}
              >
                Accept Invite
              </button>
            </div>
          </div>

          <!-- ── Org detail / members ── -->
          <div class="space-y-3">
            {#if selectedOrgDid}
              {@const callerRole = callerRoleFor(selectedOrgDid)}
              {@const isOwnerOrAdmin = callerRole === 'owner' || callerRole === 'admin'}
              <div class="rounded-[24px] border p-4 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-slate-50'}">
                <div class="mb-3 flex items-start justify-between gap-2">
                  <div class="min-w-0 flex-1">
                    <div class="text-xs font-semibold uppercase tracking-[0.2em] {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Selected org</div>
                    <div class="mt-1 break-all text-sm font-mono {isDark ? 'text-white' : 'text-gray-900'}">{selectedOrgDid}</div>
                    <div class="mt-1 text-[11px] {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">you: {callerRole}</div>
                  </div>
                </div>

                {#if isOwnerOrAdmin}
                  <div class="mb-4 rounded-2xl border p-3 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-white'}">
                    <div class="mb-2 text-xs font-semibold uppercase tracking-[0.2em] {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Edit org</div>
                    <div class="grid gap-2 sm:grid-cols-3">
                      <input bind:value={editOrgName} placeholder="name" class="rounded-xl border px-3 py-2 text-xs outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}" />
                      <input bind:value={editOrgDomain} placeholder="domain" class="rounded-xl border px-3 py-2 text-xs outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}" />
                      <select bind:value={editOrgType} class="rounded-xl border px-3 py-2 text-xs outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}">
                        <option value="personal">personal</option>
                        <option value="company">company</option>
                        <option value="npo">npo</option>
                        <option value="community">community</option>
                        <option value="team">team</option>
                      </select>
                    </div>
                    <button class="mt-2 rounded-xl border-none px-3 py-2 text-xs font-semibold text-white {isDark ? 'bg-[#2563eb]' : 'bg-blue-600'}" onclick={updateOrg}>Save changes</button>
                  </div>

                  <div class="mb-4 flex flex-col gap-2 sm:flex-row">
                    <input
                      bind:value={inviteEmail}
                      type="email"
                      placeholder="invitee@example.com"
                      class="flex-1 rounded-2xl border px-4 py-2 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
                    />
                    <select
                      bind:value={inviteRole}
                      class="rounded-2xl border px-4 py-2 text-sm outline-none {isDark ? 'border-[#334155] bg-[rgba(15,23,42,0.9)] text-white' : 'border-gray-300 bg-white text-gray-900'}"
                    >
                      <option value="member">member</option>
                      <option value="admin">admin</option>
                    </select>
                    <button
                      class="rounded-2xl border-none px-4 py-2 text-sm font-semibold text-white {isDark ? 'bg-[#2563eb]' : 'bg-blue-600'}"
                      onclick={sendOrgInvite}
                      disabled={!inviteEmail}
                    >
                      Invite
                    </button>
                  </div>
                {/if}

                <div class="text-xs font-semibold uppercase tracking-[0.2em] {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">Members ({selectedMembers.length})</div>
                <ul class="mt-2 m-0 list-none space-y-2 p-0">
                  {#each selectedMembers as member}
                    <li class="flex items-start justify-between gap-3 rounded-2xl border p-3 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)]' : 'border-gray-200 bg-white'}">
                      <div class="min-w-0 flex-1">
                        <div class="text-sm font-semibold {isDark ? 'text-white' : 'text-gray-900'}">{member.role}</div>
                        <div class="mt-1 break-all text-xs font-mono {isDark ? 'text-[#94a3b8]' : 'text-gray-500'}">{member.memberDid}</div>
                      </div>
                      {#if isOwnerOrAdmin && member.role !== 'owner'}
                        <div class="flex flex-col gap-1">
                          {#if member.role === 'member'}
                            <button class="rounded-xl border px-2 py-1 text-[11px] font-semibold {isDark ? 'border-[#334155] text-[#cbd5e1]' : 'border-gray-300 text-gray-700'}" onclick={() => updateMemberRole(member.memberDid, 'admin')}>Promote to admin</button>
                          {:else if member.role === 'admin' && callerRole === 'owner'}
                            <button class="rounded-xl border px-2 py-1 text-[11px] font-semibold {isDark ? 'border-[#334155] text-[#cbd5e1]' : 'border-gray-300 text-gray-700'}" onclick={() => updateMemberRole(member.memberDid, 'member')}>Demote to member</button>
                          {/if}
                          {#if callerRole === 'owner'}
                            <button class="rounded-xl border px-2 py-1 text-[11px] font-semibold {isDark ? 'border-[#22c55e]/40 text-[#86efac]' : 'border-green-500 text-green-700'}" onclick={() => transferOwnership(member.memberDid)}>Transfer ownership</button>
                          {/if}
                          <button class="rounded-xl border px-2 py-1 text-[11px] font-semibold {isDark ? 'border-[#3f1d1d] text-[#fca5a5]' : 'border-red-200 text-red-600'}" onclick={() => removeMember(member.memberDid)}>Remove</button>
                        </div>
                      {/if}
                    </li>
                  {/each}
                </ul>
              </div>
            {:else}
              <div class="rounded-[24px] border p-4 {isDark ? 'border-[#1e293b] bg-[rgba(2,6,23,0.7)] text-[#94a3b8]' : 'border-gray-200 bg-slate-50 text-gray-600'}">
                Select an org from the left to see members, or create one.
              </div>
            {/if}

            {#if orgStatus}
              <p class="mb-0 mt-2 text-xs {isDark ? 'text-[#93c5fd]' : 'text-blue-700'}">{orgStatus}</p>
            {/if}
          </div>
        </div>
      </section>
    {/if}
  </div>
</div>
