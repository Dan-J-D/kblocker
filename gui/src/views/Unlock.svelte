<script lang="ts">
  import { app } from "../lib/store.svelte";
  import { api, errorText, pickTextFile, type KeyHolder } from "../lib/api";
  import { clock, duration } from "../lib/time";
  import Icon from "../components/Icon.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import Spinner from "../components/Spinner.svelte";
  import WebPages from "../components/WebPages.svelte";

  let { go }: { go: (v: "now" | "holders") => void } = $props();

  type Method = "key" | "private";
  let method = $state<Method>("key");
  let hexKey = $state("");
  let privArmored = $state("");
  let passphrase = $state("");
  let needsPass = $state(false);
  let busy = $state(false);
  let error = $state("");

  let holders = $derived(app.holders.filter((h) => h.has_cipher));
  let cleanKey = $derived(hexKey.trim().toLowerCase().replace(/\s+/g, ""));
  let keyValid = $derived(/^[0-9a-f]{32}$/.test(cleanKey));
  let badChars = $derived(/[^0-9a-f]/.test(cleanKey));

  async function copyCipher(h: KeyHolder) {
    const text = await app.act(() => api.cipherFor(h.fingerprint));
    if (text) {
      await navigator.clipboard.writeText(text);
      app.flash("ok", `Copied ${h.name || "their"} encrypted key. Send it to them.`);
    }
  }

  async function submit(key: string) {
    busy = true;
    const ok = await app.act(async () => {
      await api.unblock(key);
      return true;
    }, "Unlocked. Blocking has stopped.");
    busy = false;
    if (ok) {
      hexKey = privArmored = passphrase = "";
      go("now");
    }
  }

  async function loadPriv() {
    const text = await pickTextFile("Choose a private key").catch((e) => {
      error = errorText(e);
      return null;
    });
    if (text) privArmored = text;
  }

  // Decrypts the unload key here; the private key never leaves this window
  async function decryptAndSubmit(e: SubmitEvent) {
    e.preventDefault();
    error = "";
    busy = true;
    try {
      const openpgp = await import("openpgp");
      let key = await openpgp.readPrivateKey({ armoredKey: privArmored.trim() });
      if (!key.isDecrypted()) {
        if (!passphrase) {
          needsPass = true;
          throw new Error("This private key has a passphrase. Enter it to continue.");
        }
        key = await openpgp.decryptKey({ privateKey: key, passphrase });
      }
      const ciphers = Object.values(await api.ciphers());
      let found = "";
      for (const armored of ciphers) {
        try {
          const message = await openpgp.readMessage({ armoredMessage: armored });
          const { data } = await openpgp.decrypt({ message, decryptionKeys: key });
          found = String(data).trim();
          break;
        } catch {
          // encrypted to a different key holder
        }
      }
      if (!/^[0-9a-f]{32}$/i.test(found)) {
        throw new Error("This key can't decrypt the current block. It may belong to someone who isn't a key holder.");
      }
      busy = false;
      await submit(found);
    } catch (err) {
      const msg = errorText(err);
      error = /passphrase|incorrect key/i.test(msg) && passphrase ? "That passphrase didn't work." : msg;
      busy = false;
    }
  }
</script>

<PageHeader title="Unlock">
  {#if app.blocking}
    The current block ends by itself at {clock(app.endsAt)}, in
    <span class="tabular-nums">{duration(app.remaining)}</span>.
  {:else}
    End a locked block early with help from a key holder.
  {/if}
</PageHeader>

{#if !app.blocking}
  <div class="rounded-xl border border-dashed border-line px-5 py-10 text-center">
    <Icon name="unlock" size={28} class="mx-auto text-muted/60" />
    <p class="mt-3 text-base text-muted">There's nothing to unlock. You aren't blocking right now.</p>
  </div>
{:else if !app.locked}
  <p class="max-w-[60ch] text-base text-muted">This block isn't locked with PGP, so it can be stopped without a key.</p>
  <button class="btn-quiet mt-4" disabled={busy} onclick={() => app.act(() => api.unblock(null), "Stopped blocking.")}>
    Stop blocking
  </button>
{:else}
  <ol class="space-y-4">
    <li class="rounded-xl border border-line-soft bg-panel p-5">
      <h2 class="flex items-center gap-3 text-lg font-medium">
        <span class="grid size-7 place-items-center rounded-full bg-signal/12 text-sm font-semibold text-signal">1</span>Ask a key holder
      </h2>
      <p class="mt-1 max-w-[62ch] text-base text-muted">
        Send one of them their encrypted key. They decrypt it with
        <code class="selectable font-mono text-text">gpg --decrypt</code> and send back a 32-character unload key.
      </p>
      {#if holders.length > 0}
        <div class="mt-4 text-sm text-muted">
          <p class="mb-1.5">Or send them the unblock page. Their private key stays in their browser:</p>
          <WebPages path="/unblock" />
        </div>
      {/if}
      {#if holders.length === 0}
        <p class="mt-3 text-sm text-warn">
          No encrypted copies of the current key were found. This block can only end on time.
        </p>
      {:else}
        <ul class="mt-4 overflow-hidden rounded-lg border border-line-soft">
          {#each holders as h (h.fingerprint)}
            <li class="flex h-12 items-center justify-between border-b border-line-soft bg-ink px-4 last:border-b-0">
              <span>{h.name || h.user}</span>
              <button class="btn-ghost text-sm" onclick={() => copyCipher(h)}><Icon name="copy" size={15} />Copy encrypted key</button>
            </li>
          {/each}
        </ul>
      {/if}
    </li>

    <li class="rounded-xl border border-line-soft bg-panel p-5">
      <h2 class="flex items-center gap-3 text-lg font-medium">
        <span class="grid size-7 place-items-center rounded-full bg-signal/12 text-sm font-semibold text-signal">2</span>Enter what they give you
      </h2>
      <div class="mt-3 mb-4 flex items-center gap-6 border-b border-line-soft" role="tablist">
        {#each [["key", "Unload key"], ["private", "Their private key"]] as [id, label] (id)}
          <button
            role="tab"
            aria-selected={method === id}
            class="-mb-px border-b-2 pb-2.5 text-base transition-colors duration-150
              {method === id ? 'border-signal text-text' : 'border-transparent text-muted hover:text-text'}"
            onclick={() => {
              method = id as Method;
              error = "";
            }}
          >
            {label}
          </button>
        {/each}
      </div>

      {#if method === "key"}
        <form
          class="max-w-xl"
          onsubmit={(e) => {
            e.preventDefault();
            submit(cleanKey);
          }}
        >
          <label class="label" for="unload-key">Unload key</label>
          <input
            id="unload-key"
            class="field h-10 font-mono text-base tracking-wider"
            placeholder="32 hex characters"
            spellcheck="false"
            autocomplete="off"
            bind:value={hexKey}
          />
          {#if hexKey && !keyValid}
            <p class="mt-1.5 text-sm text-muted">
              {cleanKey.length} of 32 characters{badChars ? ", and only 0–9 and a–f are allowed" : ""}.
            </p>
          {/if}
          <button class="btn-primary mt-4" disabled={!keyValid || busy}>
            {#if busy}<Spinner />Unlocking…{:else}<Icon name="unlock" size={16} />Unlock{/if}
          </button>
        </form>
      {:else}
        <form class="max-w-xl space-y-4" onsubmit={decryptAndSubmit}>
          <p class="text-sm text-muted">
            For when your key holder is with you. Their key is used only in this window and isn't saved.
          </p>
          <div>
            <div class="mb-1 flex items-baseline justify-between">
              <label class="text-sm text-muted" for="priv-key">Private key</label>
              <button type="button" class="link inline-flex items-center gap-1 text-sm" onclick={loadPriv}><Icon name="file" size={14} />Open a file…</button>
            </div>
            <textarea
              id="priv-key"
              rows="5"
              class="field h-auto resize-y py-2 font-mono text-sm"
              placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
              bind:value={privArmored}
            ></textarea>
          </div>
          {#if needsPass}
            <div>
              <label class="label" for="priv-pass">Passphrase</label>
              <input id="priv-pass" type="password" class="field max-w-xs" bind:value={passphrase} />
            </div>
          {/if}
          <button class="btn-primary" disabled={!privArmored.trim() || busy}>
            {#if busy}<Spinner />Decrypting…{:else}Decrypt and unlock{/if}
          </button>
        </form>
      {/if}
      {#if error}<p class="mt-3 max-w-xl text-sm text-danger selectable">{error}</p>{/if}
    </li>
  </ol>
{/if}
