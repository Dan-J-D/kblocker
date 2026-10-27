<script lang="ts">
  import { app } from "../lib/store.svelte";
  import { api } from "../lib/api";
  import Dialog from "../components/Dialog.svelte";
  import Icon from "../components/Icon.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import Spinner from "../components/Spinner.svelte";
  import WebPages from "../components/WebPages.svelte";

  let unloadKey = $state("");
  let confirmUnload = $state(false);
  let reloading = $state(false);
  let unloading = $state(false);

  let s = $derived(app.status);
  let keyValid = $derived(/^[0-9a-f]{32}$/i.test(unloadKey.trim()));

  async function reload() {
    reloading = true;
    await app.act(() => api.reload(), "Sites re-sent to the kernel.");
    reloading = false;
  }

  async function unload() {
    confirmUnload = false;
    unloading = true;
    await app.act(() => api.unload(unloadKey.trim()), "Module unloaded.");
    unloadKey = "";
    unloading = false;
  }
</script>

{#snippet row(label: string, good: boolean, value: string, note?: string)}
  <div class="flex items-start gap-3 border-b border-line-soft px-5 py-3.5 last:border-b-0">
    <span class="mt-1.5 size-2 shrink-0 rounded-full transition-colors duration-300 {good ? 'bg-ok' : 'bg-warn'}"></span>
    <span class="w-44 shrink-0 text-muted">{label}</span>
    <span class="min-w-0">
      {value}
      {#if note}<span class="mt-0.5 block text-sm text-muted">{note}</span>{/if}
    </span>
  </div>
{/snippet}

<PageHeader title="System">How kblocker is running on this computer.</PageHeader>

<section class="overflow-hidden rounded-xl border border-line-soft bg-panel">
  {@render row("Kernel module", !!s?.module_loaded, s?.module_loaded ? "Loaded" : "Not loaded",
    s?.module_loaded ? undefined : "Run sudo modprobe kblocker to load it.")}
  {@render row("Scheduler service", !!s?.scheduler_active, s?.scheduler_active ? "Running" : "Not running",
    s?.scheduler_active
      ? "Starts scheduled blocks and records history, even when this app is closed."
      : "Scheduled blocks won't start and history isn't recorded until it runs.")}
  {#if s && !s.scheduler_active}
    <div class="border-b border-line-soft px-5 pb-3.5 pl-[13.75rem]">
      <code class="selectable rounded-md bg-ink px-2 py-1 font-mono text-sm text-text"
        >sudo systemctl enable --now kblocker-scheduler</code
      >
    </div>
  {/if}
  <div class="flex items-start gap-3 border-b border-line-soft px-5 py-3.5">
    <span class="mt-1.5 size-2 shrink-0 rounded-full {s?.web_url ? 'bg-ok' : 'bg-line'}"></span>
    <span class="w-44 shrink-0 pt-1 text-muted">Key holder pages</span>
    <div class="min-w-0"><WebPages /></div>
  </div>
  {@render row("kblockerctl", !!s?.ctl_installed, s?.ctl_installed ? "Installed" : "Not found",
    s?.ctl_installed ? undefined : "Expected at /usr/local/bin/kblockerctl. Run sudo make install.")}
  {@render row("Protected files", true, `${s?.protected_files ?? 0}`,
    s?.enabled ? "Locked against changes during this block." : "Files are only protected during a block.")}
  {#if s?.state_restored}
    {@render row("Session", true, "Restored after a reboot")}
  {/if}
</section>

<section class="mt-10">
  <h2 class="mb-3 text-lg font-medium">Maintenance</h2>
  <div class="overflow-hidden rounded-xl border border-line-soft">
    <div class="flex items-center justify-between gap-6 border-b border-line-soft px-5 py-4">
      <div>
        <p>Reload sites</p>
        <p class="mt-0.5 text-sm text-muted">Re-send the site list to the kernel and refresh the key holders' encrypted keys.</p>
      </div>
      <button class="btn-quiet shrink-0" disabled={reloading || !s?.module_loaded} onclick={reload}>
        {#if reloading}<Spinner />{/if}Reload
      </button>
    </div>
    <div class="px-5 py-4">
      <p>Unload the module</p>
      <p class="mt-0.5 max-w-[62ch] text-sm text-muted">
        Removes kblocker from the kernel and deletes its configuration. This needs the unload key, even when you aren't
        blocking.
      </p>
      <div class="mt-3 flex max-w-xl gap-2">
        <input
          class="field font-mono"
          placeholder="Unload key"
          spellcheck="false"
          autocomplete="off"
          aria-label="Unload key"
          bind:value={unloadKey}
          disabled={!s?.module_loaded}
        />
        <button class="btn-danger shrink-0" disabled={!keyValid || unloading} onclick={() => (confirmUnload = true)}>
          {#if unloading}<Spinner />{/if}Unload module
        </button>
      </div>
    </div>
  </div>
</section>

<Dialog open={confirmUnload} title="Unload kblocker?" onclose={() => (confirmUnload = false)}>
  Blocking stops, the module is removed and your site list is deleted. Reinstall with
  <code class="font-mono text-text">sudo make install</code> to use it again.
  {#snippet actions()}
    <button class="btn-ghost" onclick={() => (confirmUnload = false)}>Cancel</button>
    <button class="btn-danger" onclick={unload}><Icon name="alert" size={15} />Unload module</button>
  {/snippet}
</Dialog>
