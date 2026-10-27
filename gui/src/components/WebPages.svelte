<script lang="ts">
  import { app } from "../lib/store.svelte";
  import { api, type WebMode } from "../lib/api";
  import Segmented from "./Segmented.svelte";
  import WebLink from "./WebLink.svelte";
  import { fade, slide } from "svelte/transition";
  import { ms, ease } from "../lib/motion";

  /** Page to link to, such as "/keys" or "/unblock"; the home page if empty */
  let { path = "" }: { path?: string } = $props();

  const modes: { id: WebMode; label: string }[] = [
    { id: "off", label: "Off" },
    { id: "local", label: "This computer" },
    { id: "lan", label: "Local network" },
    { id: "custom", label: "Custom" },
  ];

  let pending = $state<WebMode | null>(null);
  let s = $derived(app.status);

  // Custom needs an address before it can be applied, so the chosen
  // segment can run ahead of what the service is using
  let picked = $state<WebMode | null>(null);
  let mode = $derived(pending ?? picked ?? s?.web_mode ?? "local");

  let hostDraft = $state<string | null>(null);
  let portDraft = $state<string | null>(null);
  let host = $derived(hostDraft ?? (s?.web_mode === "custom" ? s.web_host : ""));
  let port = $derived(portDraft ?? String(s?.web_port ?? 8737));

  const ipRe = /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$|^[0-9a-f:]*:[0-9a-f:.]*$/i;
  let portNum = $derived(Number(port));
  let portOk = $derived(Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535);
  let hostOk = $derived(ipRe.test(host.trim()));
  let changed = $derived(
    mode !== s?.web_mode || portNum !== s?.web_port || (mode === "custom" && host.trim() !== s?.web_host),
  );
  let canSave = $derived(portOk && (mode !== "custom" || hostOk) && changed && !pending);

  const done: Record<WebMode, string> = {
    off: "Key holder pages turned off.",
    local: "Key holder pages hosted on this computer.",
    lan: "Key holder pages shared on your network.",
    custom: "Key holder pages moved to the new address.",
  };

  async function apply(next: WebMode) {
    pending = next;
    const keepPort = portOk && portNum !== s?.web_port ? portNum : undefined;
    const ok = await app.act(async () => {
      await api.setWebPages(next, next === "custom" ? host.trim() : undefined, next === "off" ? undefined : keepPort);
      return true;
    }, done[next]);
    if (ok) {
      picked = hostDraft = portDraft = null;
    }
    pending = null;
  }

  function choose(next: WebMode) {
    if (pending) return;
    if (next === "custom") {
      picked = "custom";
      return;
    }
    picked = null;
    if (next !== s?.web_mode) apply(next);
  }

  function save(e: SubmitEvent) {
    e.preventDefault();
    if (canSave) apply(mode);
  }

  let fixedHost = $derived(mode === "local" ? "127.0.0.1" : "All addresses");
</script>

<div class="flex flex-wrap items-center gap-3">
  <Segmented
    label="Host key holder pages"
    value={mode}
    options={modes.map((m) => ({ value: m.id, label: m.label }))}
    onchange={choose}
    disabled={!!pending || !s?.ctl_installed}
    busy={pending}
  />
  {#if s?.web_url && mode === s.web_mode && !pending && !changed}
    <WebLink url="{s.web_url}{path}" />
  {/if}
</div>

{#if mode !== "off"}
  <form class="mt-2.5 flex flex-wrap items-end gap-2" onsubmit={save} transition:slide={{ duration: ms(180), easing: ease }}>
    <div>
      <label class="label" for="web-host-{path}">IP address</label>
      {#if mode === "custom"}
        <input
          id="web-host-{path}"
          class="field h-8 w-44 font-mono text-sm {host && !hostOk ? 'outline-2 -outline-offset-1 outline-danger' : ''}"
          placeholder="192.168.1.20"
          spellcheck="false"
          autocomplete="off"
          bind:value={() => host, (v) => (hostDraft = v)}
        />
      {:else}
        <input id="web-host-{path}" class="field h-8 w-44 font-mono text-sm text-muted" value={fixedHost} disabled />
      {/if}
    </div>
    <div>
      <label class="label" for="web-port-{path}">Port</label>
      <input
        id="web-port-{path}"
        class="field h-8 w-24 font-mono text-sm tabular-nums [appearance:textfield] {portOk ? '' : 'outline-2 -outline-offset-1 outline-danger'}"
        type="number"
        min="1"
        max="65535"
        bind:value={() => port, (v) => (portDraft = String(v ?? ""))}
      />
    </div>
    {#if changed}
      <button class="btn-primary h-8" disabled={!canSave} in:fade={{ duration: ms(120) }}>
        {pending ? "Saving…" : "Save address"}
      </button>
      {#if picked || hostDraft !== null || portDraft !== null}
        <button
          type="button"
          class="btn-ghost h-8"
          onclick={() => (picked = hostDraft = portDraft = null)}
          in:fade={{ duration: ms(120) }}>Cancel</button
        >
      {/if}
    {/if}
  </form>
  {#if mode === "custom" && host.trim() && !hostOk}
    <p class="mt-1.5 text-sm text-danger">{host.trim()} isn't an IP address. Use one like 192.168.1.20.</p>
  {:else if !portOk}
    <p class="mt-1.5 text-sm text-danger">The port must be a number from 1 to 65535.</p>
  {/if}
{/if}

<p class="mt-1.5 text-sm text-muted">
  {#if !s?.scheduler_active && mode !== "off"}
    The scheduler service hosts these pages and isn't running. Start it with
    <code class="selectable font-mono text-text">sudo systemctl enable --now kblocker-scheduler</code>.
  {:else if mode === "off"}
    Not hosted. Key holders can still use the encrypted key with <code class="font-mono text-text">gpg</code>.
  {:else if mode === "local"}
    Only reachable from this computer. Choose Local network to open it on a key holder's phone or laptop.
  {:else if mode === "custom"}
    Listens on this one address only, such as this computer's address on a VPN. The setting is saved and survives
    restarts.
  {:else}
    Any device on your network can open it. Unlocking still needs a key holder's private key, and keys added
    during a block can't unlock that block.
  {/if}
</p>
