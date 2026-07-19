<script lang="ts">
  const app = {
  "title": "Worker",
  "project": "etzhayyim-project-auth",
  "name": "worker",
  "kind": "worker",
  "routeCount": 0,
  "routes": [],
  "vars": [],
  "xrpc": true,
  "relativePath": "60-apps/etzhayyim-project-auth/worker/svelte/src/routes/+page.svelte"
};
</script>

<svelte:head>
  <title>{app.name}</title>
</svelte:head>

<main>
  <section class="top">
    <p>Cloudflare {app.kind}</p>
    <h1>{app.title}</h1>
    <span>{app.name}</span>
  </section>

  <section class="facts">
    <div><span>Project</span><strong>{app.project}</strong></div>
    <div><span>Routes</span><strong>{app.routeCount}</strong></div>
    <div><span>XRPC</span><strong>{app.xrpc ? 'enabled' : 'not configured'}</strong></div>
  </section>

  <section class="panel">
    <h2>Public Routes</h2>
    {#if app.routes.length}
      <ul>
        {#each app.routes as route}
          <li>{route}</li>
        {/each}
      </ul>
    {:else}
      <p class="muted">No public route is declared next to this app surface.</p>
    {/if}
  </section>

  <section class="panel">
    <h2>Runtime Bindings</h2>
    {#if app.vars.length}
      <ul class="chips">
        {#each app.vars as key}
          <li>{key}</li>
        {/each}
      </ul>
    {:else}
      <p class="muted">No public vars are declared in the nearest wrangler config.</p>
    {/if}
  </section>

  <section class="panel path">
    <h2>Source</h2>
    <p>{app.relativePath}</p>
  </section>
</main>

<style>
  :global(body) { margin: 0; background: #11161d; color: #eef4f8; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  main { min-height: 100vh; padding: 24px; }
  .top { margin-bottom: 18px; }
  .top p, .top span, .muted, h2, .facts span { color: #96a6b8; }
  .top p { margin: 0 0 8px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
  h1, h2, p { margin: 0; }
  h1 { font-size: clamp(28px, 5vw, 48px); line-height: 1.05; }
  .top span { display: block; margin-top: 8px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; overflow-wrap: anywhere; }
  .facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 12px; }
  .facts div, .panel { border: 1px solid #2b3948; border-radius: 8px; background: #171f28; }
  .facts div { padding: 14px; }
  .facts span { display: block; margin-bottom: 8px; font-size: 12px; }
  .facts strong { overflow-wrap: anywhere; }
  .panel { margin-bottom: 12px; padding: 16px; }
  h2 { margin-bottom: 12px; font-size: 13px; text-transform: uppercase; }
  ul { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
  li, .path p { border: 1px solid #263443; border-radius: 6px; background: #101720; padding: 9px 10px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; overflow-wrap: anywhere; }
  .chips { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
  @media (max-width: 760px) { main { padding: 18px; } .facts { grid-template-columns: 1fr; } }
</style>
