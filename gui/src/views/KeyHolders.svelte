<script lang="ts">
  import { app } from "../lib/store.svelte";
  import { api, errorText, pickTextFile, savePrivateFile, type KeyHolder } from "../lib/api";
  import { fly, fade } from "svelte/transition";
  import { flip } from "svelte/animate";
  import { flipOpts, item, ms } from "../lib/motion";
  import Dialog from "../components/Dialog.svelte";
  import Icon from "../components/Icon.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import Spinner from "../components/Spinner.svelte";
  import WebPages from "../components/WebPages.svelte";
  import Avatar from "../components/Avatar.svelte";

  type Mode = "link" | "create" | "import";
  let mode = $state<Mode>("link");

  // Import
  let name = $state("");
  let armored = $state("");

  // Create
  let newName = $state("");
  let newEmail = $state("");
  let passphrase = $state("");
  let generated = $state<{ priv: string; pub: string; fp: string } | null>(null);
  let privSaved = $state(false);

  let busy = $state(false);
  let formError = $state("");
  let removing = $state<KeyHolder | null>(null);

  const groupFp = (fp: string) => fp.match(/.{1,4}/g)?.join(" ") ?? fp;

  async function loadFile() {
    const text = await pickTextFile("Choose a public key").catch((e) => {
      formError = errorText(e);
      return null;
    });
    if (text) armored = text;
  }

  async function importKey(e: SubmitEvent) {
    e.preventDefault();
    formError = "";
    if (armored.includes("PRIVATE KEY")) {
      formError = "That's a private key. Ask for their public key instead; the private half should never leave them.";
      return;
    }
    if (!armored.includes("BEGIN PGP PUBLIC KEY")) {
      formError = "Paste an ASCII-armored public key, starting with -----BEGIN PGP PUBLIC KEY BLOCK-----.";
      return;
    }
    busy = true;
    const ok = await app.act(async () => {
      await api.addKeyHolder(armored, name);
      return true;
    }, `Added ${name || "key holder"}.`);
    busy = false;
    if (ok) {
      name = "";
      armored = "";
    }
  }

  async function generate(e: SubmitEvent) {
    e.preventDefault();
    formError = "";
    busy = true;
    try {
      const openpgp = await import("openpgp");
      const { privateKey, publicKey } = await openpgp.generateKey({
        type: "ecc",
        // The legacy curve name is the one GnuPG 2.2+ can encrypt to
        curve: "curve25519Legacy",
        userIDs: [{ name: newName.trim(), email: newEmail.trim() || undefined }],
        passphrase: passphrase || undefined,
        format: "armored",
      });
      const key = await openpgp.readKey({ armoredKey: publicKey });
      generated = { priv: privateKey, pub: publicKey, fp: key.getFingerprint().toUpperCase() };
      privSaved = false;
    } catch (err) {
      formError = errorText(err);
    }
    busy = false;
  }

  async function savePriv() {
    if (!generated) return;
    const slug = newName.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-") || "kblocker";
    try {
      privSaved = (await savePrivateFile(`${slug}-private.asc`, generated.priv)) || privSaved;
    } catch (err) {
      formError = errorText(err);
    }
  }

  async function registerGenerated() {
    if (!generated) return;
    busy = true;
    const ok = await app.act(async () => {
      await api.addKeyHolder(generated!.pub, newName);
      return true;
    }, `Added ${newName || "key holder"}.`);
    busy = false;
    if (ok) {
      generated = null;
      newName = newEmail = passphrase = "";
    }
  }

  async function copyCipher(h: KeyHolder) {
    const text = await app.act(() => api.cipherFor(h.fingerprint));
    if (text) {
      await navigator.clipboard.writeText(text);
      app.flash("ok", `Copied the encrypted key for ${h.name || "this holder"}. Send it to them when you need to unlock.`);
    }
  }

  async function confirmRemove() {
    const h = removing!;
    removing = null;
    await app.act(() => api.removeKeyHolder(h.fingerprint), `Removed ${h.name || "key holder"}.`);
  }

  let onlyHolderInLock = $derived(
    !!removing && app.locked && app.holders.filter((h) => h.has_cipher).length <= 1 && removing.has_cipher,
  );
</script>

<PageHeader title="Key holders">
  A key holder is someone you trust, like a friend or partner. Each block's key is locked so only they can open it, so
  ending a block early means asking them. That pause is what makes a block stick.
</PageHeader>

{#if app.holders.length === 0}
  <p class="rounded-xl border border-dashed border-line px-5 py-8 text-center text-base text-muted">
    No key holders yet. The easiest way to add one is to send them a link, below.
  </p>
{:else}
  <ul class="overflow-hidden rounded-xl border border-line-soft">
    {#each app.holders as h (h.fingerprint)}
      <li
        animate:flip={flipOpts}
        in:fly={{ y: 4, ...item }}
        out:fade={{ duration: ms(120) }}
        class="flex items-start justify-between gap-6 border-b border-line-soft px-4 py-4 last:border-b-0"
      >
        <Avatar name={h.name || h.user || "?"} seed={h.fingerprint} />
        <div class="min-w-0 flex-1">
          <p class="font-medium">
            {h.name || h.user || "Unnamed key"}
            {#if app.blocking && h.has_cipher}
              <span class="ml-2 inline-flex items-center gap-1 rounded-full bg-signal/10 px-2 py-0.5 align-middle text-xs font-medium text-signal"
                ><Icon name="lock" size={12} />Can unlock this block</span
              >
            {/if}
          </p>
          {#if h.name && h.user}<p class="text-sm text-muted">{h.user}</p>{/if}
          <p class="selectable mt-1 font-mono text-sm text-muted">{groupFp(h.fingerprint)}</p>
        </div>
        <div class="flex shrink-0 gap-1">
          {#if h.has_cipher}
            <button class="btn-ghost text-sm" onclick={() => copyCipher(h)}><Icon name="copy" size={15} />Copy encrypted key</button>
          {/if}
          <button class="btn-ghost text-sm hover:text-danger" onclick={() => (removing = h)}>Remove</button>
        </div>
      </li>
    {/each}
  </ul>
{/if}

<section class="mt-10 rounded-xl border border-line-soft bg-panel p-5 pt-3">
  <div class="mb-5 flex items-center gap-x-6 overflow-x-auto border-b border-line-soft" role="tablist">
    {#each [["link", "Send them a link"], ["create", "Make a key for them"], ["import", "Use their PGP key"]] as [id, label] (id)}
      <button
        role="tab"
        aria-selected={mode === id}
        class="-mb-px shrink-0 border-b-2 pt-2 pb-2.5 text-base whitespace-nowrap transition-colors duration-150
          {mode === id ? 'border-signal text-text' : 'border-transparent text-muted hover:text-text'}"
        onclick={() => {
          mode = id as Mode;
          formError = "";
        }}
      >
        {label}
      </button>
    {/each}
  </div>

  {#if mode === "link"}
    <div class="max-w-xl space-y-4">
      <ol class="space-y-2 text-base">
        <li><span class="text-muted">1.</span> Send them the link below. It opens a page in their browser.</li>
        <li><span class="text-muted">2.</span> They enter their name, create a key, and download the private key file it gives them to keep.</li>
        <li><span class="text-muted">3.</span> They show up in your list here straight away. Nothing to install, nothing to copy.</li>
      </ol>
      <WebPages path="/keys" />
      <p class="text-sm text-muted">
        To end a block early later, they open the same address with <span class="font-mono text-text">/unblock</span>
        and pick their key file.
      </p>
    </div>
  {:else if mode === "import"}
    <form class="max-w-xl space-y-4" onsubmit={importKey}>
      <div>
        <label class="label" for="holder-name">Name</label>
        <input id="holder-name" class="field max-w-xs" placeholder="Sam" bind:value={name} />
      </div>
      <div>
        <div class="mb-1 flex items-baseline justify-between">
          <label class="text-sm text-muted" for="holder-key">Public key</label>
          <button type="button" class="link inline-flex items-center gap-1 text-sm" onclick={loadFile}><Icon name="file" size={14} />Open a file…</button>
        </div>
        <textarea
          id="holder-key"
          rows="6"
          class="field h-auto resize-y py-2 font-mono text-sm"
          placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
          bind:value={armored}
        ></textarea>
      </div>
      {#if formError}<p class="text-sm text-danger">{formError}</p>{/if}
      <button class="btn-primary" disabled={busy || !armored.trim()}>{#if busy}<Spinner />Adding…{:else}Add key holder{/if}</button>
    </form>
  {:else if !generated}
    <form class="max-w-xl space-y-4" onsubmit={generate}>
      <p class="text-sm text-muted">
        The key pair is made on this computer. You'll save the private key and hand it to your key holder; kblocker
        keeps only the public half.
      </p>
      <div class="grid gap-3 sm:grid-cols-2">
        <div>
          <label class="label" for="gen-name">Key holder's name</label>
          <input id="gen-name" class="field" placeholder="Sam" bind:value={newName} required />
        </div>
        <div>
          <label class="label" for="gen-email">Email (optional)</label>
          <input id="gen-email" type="email" class="field" placeholder="sam@example.org" bind:value={newEmail} />
        </div>
      </div>
      <div>
        <label class="label" for="gen-pass">Passphrase (optional)</label>
        <input id="gen-pass" type="password" class="field max-w-xs" bind:value={passphrase} autocomplete="new-password" />
        <p class="mt-1 text-sm text-muted">Share it with your key holder separately from the key file.</p>
      </div>
      {#if formError}<p class="text-sm text-danger">{formError}</p>{/if}
      <button class="btn-primary" disabled={busy || !newName.trim()}>{#if busy}<Spinner />Creating…{:else}Create key pair{/if}</button>
    </form>
  {:else}
    <div class="max-w-xl space-y-4">
      <p class="text-base">Key pair created for {newName}.</p>
      <p class="selectable font-mono text-sm text-muted">{groupFp(generated.fp)}</p>
      <ol class="space-y-3 text-base">
        <li class="flex items-center justify-between gap-4 rounded-lg border border-line-soft bg-ink px-4 py-3">
          <span>
            <span class="text-muted">1.</span> Save the private key and give it to {newName}.
            <span class="block text-sm text-muted">It isn't stored anywhere else. Don't keep a copy yourself.</span>
          </span>
          <button class="btn-quiet shrink-0" onclick={savePriv}>
            {#if privSaved}<Icon name="check" size={15} class="text-ok" />Saved{:else}Save private key…{/if}
          </button>
        </li>
        <li class="flex items-center justify-between gap-4 rounded-lg border border-line-soft bg-ink px-4 py-3">
          <span><span class="text-muted">2.</span> Register the public key with kblocker.</span>
          <button class="btn-primary shrink-0" disabled={!privSaved || busy} onclick={registerGenerated}>
            {busy ? "Adding…" : "Add key holder"}
          </button>
        </li>
      </ol>
      {#if formError}<p class="text-sm text-danger">{formError}</p>{/if}
      <button class="btn-ghost text-sm" onclick={() => (generated = null)}>Start over</button>
    </div>
  {/if}
</section>

<Dialog open={!!removing} title="Remove {removing?.name || 'this key holder'}?" onclose={() => (removing = null)}>
  {#if onlyHolderInLock}
    <strong class="text-danger">They're the only one who can unlock the current block.</strong> Removing them deletes
    their encrypted copy of the key, so this block can't end early. It still ends on time.
  {:else if removing?.has_cipher}
    Their encrypted copy of the current key is deleted too. Future blocks won't be encrypted to them.
  {:else}
    Future blocks won't be encrypted to them.
  {/if}
  {#snippet actions()}
    <button class="btn-ghost" onclick={() => (removing = null)}>Cancel</button>
    <button class="btn-danger" onclick={confirmRemove}>Remove</button>
  {/snippet}
</Dialog>
