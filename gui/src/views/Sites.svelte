<script lang="ts">
  import { fly, fade } from "svelte/transition";
  import { flip } from "svelte/animate";
  import { app } from "../lib/store.svelte";
  import { api } from "../lib/api";
  import { flipOpts, item, ms } from "../lib/motion";
  import Icon from "../components/Icon.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import Spinner from "../components/Spinner.svelte";

  type Site = { name: string; domains: string[] };
  type Category = { name: string; sites: Site[] };

  // Base domains only: each entry also covers its subdomains
  const categories: Category[] = [
    {
      name: "Social media",
      sites: [
        { name: "Facebook", domains: ["facebook.com", "fb.com", "fbcdn.net", "messenger.com"] },
        { name: "Instagram", domains: ["instagram.com", "cdninstagram.com"] },
        { name: "X", domains: ["x.com", "twitter.com", "twimg.com"] },
        { name: "TikTok", domains: ["tiktok.com", "tiktokcdn.com", "tiktokv.com"] },
        { name: "Reddit", domains: ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"] },
        { name: "Snapchat", domains: ["snapchat.com", "sc-cdn.net"] },
        { name: "Threads", domains: ["threads.net", "threads.com"] },
        { name: "Bluesky", domains: ["bsky.app", "bsky.social"] },
        { name: "LinkedIn", domains: ["linkedin.com", "licdn.com"] },
        { name: "Pinterest", domains: ["pinterest.com", "pinimg.com"] },
        { name: "Tumblr", domains: ["tumblr.com"] },
      ],
    },
    {
      name: "Video",
      sites: [
        { name: "YouTube", domains: ["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com"] },
        { name: "Twitch", domains: ["twitch.tv", "ttvnw.net", "jtvnw.net"] },
        { name: "Kick", domains: ["kick.com"] },
        { name: "Netflix", domains: ["netflix.com", "nflxvideo.net", "nflximg.net"] },
        { name: "Prime Video", domains: ["primevideo.com"] },
        { name: "Disney+", domains: ["disneyplus.com"] },
        { name: "Hulu", domains: ["hulu.com"] },
        { name: "Max", domains: ["max.com"] },
      ],
    },
    {
      name: "News",
      sites: [
        { name: "Hacker News", domains: ["news.ycombinator.com"] },
        { name: "Google News", domains: ["news.google.com"] },
        { name: "CNN", domains: ["cnn.com"] },
        { name: "Fox News", domains: ["foxnews.com"] },
        { name: "BBC", domains: ["bbc.com", "bbc.co.uk"] },
        { name: "New York Times", domains: ["nytimes.com"] },
        { name: "The Guardian", domains: ["theguardian.com"] },
        { name: "Washington Post", domains: ["washingtonpost.com"] },
      ],
    },
    {
      name: "Chat",
      sites: [
        { name: "Discord", domains: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net"] },
        { name: "WhatsApp Web", domains: ["web.whatsapp.com"] },
        { name: "Telegram Web", domains: ["web.telegram.org"] },
      ],
    },
    {
      name: "Shopping",
      sites: [
        { name: "Amazon", domains: ["amazon.com"] },
        { name: "eBay", domains: ["ebay.com"] },
        { name: "Etsy", domains: ["etsy.com"] },
        { name: "AliExpress", domains: ["aliexpress.com"] },
        { name: "Temu", domains: ["temu.com"] },
        { name: "Shein", domains: ["shein.com"] },
      ],
    },
    {
      name: "Games",
      sites: [
        { name: "Steam", domains: ["steampowered.com", "steamcommunity.com"] },
        { name: "Epic Games", domains: ["epicgames.com"] },
        { name: "Roblox", domains: ["roblox.com"] },
        { name: "Chess.com", domains: ["chess.com"] },
        { name: "Lichess", domains: ["lichess.org"] },
      ],
    },
  ];

  let input = $state("");
  let error = $state("");
  let saving = $state(false);
  // Shown immediately while the change is applied; the next status
  // refresh replaces it, which also rolls back a failed change
  let optimistic = $state<string[] | null>(null);

  let domains = $derived(optimistic ?? app.status?.domains ?? []);
  let locked = $derived(app.blocking);
  let available = $derived(!!app.status?.module_loaded);
  let editable = $derived(!locked && available);

  const domainRe = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

  function normalize(raw: string): string {
    return raw
      .trim()
      .toLowerCase()
      .replace(/^[a-z]+:\/\//, "")
      .replace(/[/?#].*$/, "")
      .replace(/:\d+$/, "")
      .replace(/\.$/, "")
      // Blocking a domain covers its subdomains, so *.x.com and www.x.com are x.com
      .replace(/^(\*\.|www\.)+/, "");
  }

  async function save(next: string[], done: string, removed?: string) {
    optimistic = next;
    saving = true;
    await app.act(() => api.setDomains(next, removed), done);
    optimistic = null;
    saving = false;
  }

  async function add(e?: SubmitEvent) {
    e?.preventDefault();
    error = "";
    const parts = input.split(/[\s,]+/).map(normalize).filter(Boolean);
    const bad = parts.filter((p) => !domainRe.test(p));
    if (bad.length) {
      error = `${bad.join(", ")} ${bad.length === 1 ? "isn't a domain" : "aren't domains"}. Use a name like example.com.`;
      return;
    }
    const fresh = [...new Set(parts)].filter((p) => !domains.includes(p));
    if (fresh.length === 0) {
      error = parts.length ? "Already on the list." : "";
      return;
    }
    input = "";
    await save([...domains, ...fresh], fresh.length === 1 ? `Added ${fresh[0]}.` : `Added ${fresh.length} sites.`);
  }

  const covered = (list: string[]) => list.every((d) => domains.includes(d));
  const categoryDomains = (c: Category) => [...new Set(c.sites.flatMap((s) => s.domains))];

  // Category to show first; social media unless the user picks another
  let openCategory = $state(categories[0].name);
  let shown = $derived(categories.find((c) => c.name === openCategory) ?? categories[0]);
  let all = $derived(categoryDomains(shown));
  let allDone = $derived(covered(all));

  function addPreset(name: string, list: string[]) {
    const fresh = list.filter((d) => !domains.includes(d));
    if (fresh.length) save([...domains, ...fresh], `Added ${name}.`);
  }

  function remove(d: string) {
    save(
      domains.filter((x) => x !== d),
      `Removed ${d}.`,
      d,
    );
  }
</script>

<PageHeader title="Sites">
  Each entry also covers its subdomains, so <span class="font-mono text-text">x.com</span> blocks
  <span class="font-mono text-text">www.x.com</span> but not <span class="font-mono text-text">netflix.com</span>.
  {#snippet aside()}
    <span class="tabular-nums">{domains.length} {domains.length === 1 ? "site" : "sites"}</span>
  {/snippet}
</PageHeader>

{#if locked}
  <p class="mb-5 flex items-center gap-2 rounded-lg border border-line-soft bg-panel px-4 py-3 text-sm text-muted">
    <Icon name="lock" size={15} />Sites can't be changed while a block is running.
  </p>
{:else if !available}
  <p class="mb-5 flex items-center gap-2 rounded-lg border border-warn/30 bg-warn/[0.06] px-4 py-3 text-sm text-warn">
    <Icon name="alert" size={15} />Load the kblocker module to change sites.
  </p>
{/if}

<section class="rounded-xl border border-line-soft bg-panel p-5">
  <form class="flex gap-2" onsubmit={add}>
    <input
      class="field h-10 flex-1 font-mono"
      placeholder="example.com"
      aria-label="Site to block"
      bind:value={input}
      oninput={() => (error = "")}
      disabled={!editable}
    />
    <button class="btn-primary h-10" disabled={!editable || !input.trim()}>
      <Icon name="plus" size={16} />Add site
    </button>
  </form>
  {#if error}
    <p class="mt-2 text-sm text-danger" transition:fade={{ duration: ms(150) }}>{error}</p>
  {:else}
    <p class="mt-2 text-sm text-muted">Separate several sites with spaces or commas.</p>
  {/if}

  <div class="mt-5 border-t border-line-soft pt-4">
    <div class="flex flex-wrap items-center gap-1" role="tablist" aria-label="Preset categories">
      <span class="mr-2 text-sm text-muted">Quick add</span>
      {#each categories as c (c.name)}
        <button
          role="tab"
          aria-selected={c.name === openCategory}
          class="h-7 rounded-md px-2.5 text-sm transition-colors duration-150
            {c.name === openCategory ? 'bg-raised text-text' : 'text-muted hover:text-text'}"
          onclick={() => (openCategory = c.name)}
        >
          {c.name}{#if covered(categoryDomains(c))}<Icon name="check" size={12} class="ml-1 inline text-signal" />{/if}
        </button>
      {/each}
    </div>

    {#key shown.name}
      <div class="mt-3 flex flex-wrap items-center gap-1.5" role="tabpanel" in:fade={{ duration: ms(120) }}>
        <button
          class="inline-flex h-7 items-center gap-1 rounded-full border px-3 text-sm font-medium transition-all duration-150
            {allDone
            ? 'border-transparent bg-signal/10 text-signal/80'
            : 'border-signal/40 text-signal hover:bg-signal/10 active:scale-[0.97]'}"
          disabled={allDone || !editable}
          title={all.join(", ")}
          onclick={() => addPreset(shown.name.toLowerCase(), all)}
        >
          {#if allDone}<Icon name="check" size={13} />{:else}<Icon name="plus" size={13} />{/if}All {shown.name.toLowerCase()}
        </button>
        {#each shown.sites as g (g.name)}
          {@const done = covered(g.domains)}
          <button
            class="inline-flex h-7 items-center gap-1 rounded-full border px-3 text-sm transition-all duration-150
              {done
              ? 'border-transparent bg-signal/10 text-signal/80'
              : 'border-line text-muted hover:border-muted hover:bg-hover hover:text-text active:scale-[0.97]'}"
            disabled={done || !editable}
            title={g.domains.join(", ")}
            onclick={() => addPreset(g.name, g.domains)}
          >
            {#if done}<Icon name="check" size={13} />{/if}{g.name}
          </button>
        {/each}
      </div>
    {/key}
  </div>
</section>

<section class="mt-9">
  <h2 class="mb-3 flex items-center gap-2 text-lg font-medium">
    Blocked sites
    {#if saving}<span class="text-muted" in:fade={{ duration: ms(120) }}><Spinner /></span>{/if}
  </h2>
  {#if domains.length === 0}
    <p class="rounded-xl border border-dashed border-line px-5 py-8 text-center text-base text-muted">
      No sites yet. Add the ones that pull you away, then start a block.
    </p>
  {:else}
    <ul class="overflow-hidden rounded-xl border border-line-soft">
      {#each domains as d (d)}
        <li
          animate:flip={flipOpts}
          in:fly={{ x: -8, ...item }}
          out:fade={{ duration: ms(120) }}
          class="group flex h-11 items-center justify-between border-b border-line-soft bg-ink px-4 transition-colors last:border-b-0 hover:bg-hover"
        >
          <span class="selectable flex items-center gap-3 font-mono text-base">
            <span class="size-1.5 rounded-full {locked ? 'bg-signal' : 'bg-line'} transition-colors duration-300"></span>
            {d}
          </span>
          {#if editable}
            <button
              class="btn-ghost h-7 text-sm opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100 hover:text-danger"
              onclick={() => remove(d)}
              aria-label="Remove {d}">Remove</button
            >
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>
