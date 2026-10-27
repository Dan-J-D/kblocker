<script lang="ts">
  import { fly, slide } from "svelte/transition";
  import { flip } from "svelte/animate";
  import { app } from "../lib/store.svelte";
  import { api } from "../lib/api";
  import { enter, flipOpts, item, ms } from "../lib/motion";
  import {
    activeOccurrence,
    clock,
    clockHHMM,
    dayWord,
    duration,
    durationMinutes,
    minutesSinceMidnight,
    nextOccurrence,
    segmentsForDay,
    DAY,
  } from "../lib/time";
  import DayRibbon, { type RibbonSegment } from "../components/DayRibbon.svelte";
  import HourAxis from "../components/HourAxis.svelte";
  import Dialog from "../components/Dialog.svelte";
  import Icon from "../components/Icon.svelte";
  import Spinner from "../components/Spinner.svelte";
  import GetStarted from "../components/GetStarted.svelte";
  import Segmented from "../components/Segmented.svelte";

  let { go }: { go: (v: "schedule" | "sites" | "holders" | "unlock" | "system") => void } = $props();

  const presets = [25, 50, 90, 180];
  let minutes = $state(50);
  let custom = $state("");
  let unlocked = $state(false);
  let confirming = $state(false);
  let busy = $state(false);
  let shownKey = $state<string | null>(null);
  let copied = $state(false);

  let chosen = $derived(custom ? Math.max(0, Math.floor(Number(custom))) : minutes);
  let s = $derived(app.status);
  let holders = $derived(app.holders.length);
  let blocks = $derived(app.schedule.blocks.filter((b) => b.enabled));

  let nowMin = $derived(minutesSinceMidnight(app.now));
  let openWindow = $derived(activeOccurrence(blocks, app.now));
  let next = $derived(nextOccurrence(blocks, app.now));

  let upcoming = $derived.by(() => {
    const out = [];
    let t = app.now;
    for (let i = 0; i < 4; i++) {
      const o = nextOccurrence(blocks, t);
      if (!o) break;
      out.push(o);
      t = new Date(o.start.getTime() + 1000);
    }
    return out;
  });

  let todaySegments = $derived.by((): RibbonSegment[] => {
    const segs: RibbonSegment[] = segmentsForDay(blocks, app.now.getDay()).map((seg) => ({
      key: `${seg.block.id}${seg.carried ? "c" : ""}`,
      start: seg.start,
      end: seg.end,
      kind: "scheduled",
      label: seg.carried ? "" : seg.block.name,
      title: `${seg.block.name || "Scheduled block"}: ${clockHHMM(seg.block.start)} to ${clockHHMM(seg.block.end)}`,
    }));
    if (app.blocking) {
      const end = Math.min(nowMin + app.remaining / 60, DAY);
      segs.push({ key: "active", start: nowMin, end, kind: "active", title: `Blocking until ${clock(app.endsAt)}` });
    }
    return segs;
  });

  let todayLabel = $derived(app.now.toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" }));
  let canStart = $derived(!!s?.module_loaded && chosen >= 1 && (s?.domains.length ?? 0) > 0 && (holders > 0 || unlocked));
  let endTime = $derived(clock(new Date(app.now.getTime() + chosen * 60_000)));

  async function start() {
    confirming = false;
    busy = true;
    const res = await app.act(() => api.enable(chosen, holders === 0), `Blocking for ${durationMinutes(chosen)}.`);
    busy = false;
    if (res?.key) shownKey = res.key;
  }

  async function stopUnlocked() {
    busy = true;
    await app.act(() => api.unblock(null), "Stopped blocking.");
    busy = false;
  }

  async function copyKey() {
    await navigator.clipboard.writeText(shownKey!);
    copied = true;
    setTimeout(() => (copied = false), 1600);
  }
</script>

<!-- Status: the one thing every visit needs answered -->
<header class="mb-9">
  {#if !s}
    <div class="h-[2.75rem] w-80 animate-pulse rounded-lg bg-panel"></div>
    <div class="mt-4 h-5 w-96 animate-pulse rounded bg-panel"></div>
  {:else}
    {#key `${s.module_loaded}-${app.blocking}`}
      <div in:fly={enter}>
        {#if !s.module_loaded}
          <span class="mb-4 inline-flex items-center gap-1.5 rounded-full bg-warn/10 px-2.5 py-1 text-sm font-medium text-warn">
            <Icon name="alert" size={14} />Kernel module not loaded
          </span>
          <h1 class="text-display font-medium tracking-[-0.025em]">kblocker isn't running</h1>
          <p class="mt-3 max-w-[60ch] text-lg text-muted">
            Load it with <code class="selectable rounded bg-panel px-1.5 py-0.5 font-mono text-base text-text">sudo modprobe kblocker</code>,
            or install it first with
            <code class="selectable rounded bg-panel px-1.5 py-0.5 font-mono text-base text-text">sudo make install</code>.
          </p>
        {:else if app.blocking}
          <span
            class="mb-4 inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-sm font-medium
              {app.locked ? 'bg-signal/12 text-signal' : 'bg-warn/10 text-warn'}"
          >
            <Icon name={app.locked ? "lock" : "unlock"} size={14} />{app.locked ? "Locked with PGP" : "Not locked"}
          </span>
          <h1 class="text-display font-medium tracking-[-0.025em]">
            Blocking until {clock(app.endsAt)}{#if dayWord(app.endsAt, app.now) !== "today"}<span class="text-muted"
                >{" "}{dayWord(app.endsAt, app.now)}</span
              >{/if}
          </h1>
          <p class="mt-3 text-lg text-muted">
            <span class="font-medium text-text tabular-nums">{duration(app.remaining)}</span> to go.
            {app.locked ? "Ending early takes one of your key holders." : "Anyone with root can stop it."}
          </p>
        {:else}
          <h1 class="text-display font-medium tracking-[-0.025em]">Not blocking</h1>
          <p class="mt-3 text-lg text-muted">
            {#if openWindow && !s.scheduler_active}
              <span class="text-text">{openWindow.block.name || "A scheduled block"}</span> should be on now, but the
              scheduler service isn't running.
              <button class="link" onclick={() => go("system")}>See how to start it</button>
            {:else if openWindow && holders === 0}
              <span class="text-text">{openWindow.block.name || "A scheduled block"}</span> should be on now, but scheduled
              blocks need a key holder to lock them.
              <button class="link" onclick={() => go("holders")}>Add a key holder</button>
            {:else if openWindow}
              <span class="text-text">{openWindow.block.name || "This scheduled block"}</span> was unlocked early.
              {next ? `The next one starts ${dayWord(next.start, app.now)} at ${clock(next.start)}.` : ""}
            {:else if next}
              Next block starts {dayWord(next.start, app.now)} at
              <span class="font-medium text-text">{clock(next.start)}</span>.
            {:else}
              Nothing scheduled. <button class="link" onclick={() => go("schedule")}>Set up a weekly schedule</button>
            {/if}
          </p>
        {/if}
      </div>
    {/key}
  {/if}
</header>

{#if s?.module_loaded && !app.blocking}
  <GetStarted {go} />
{/if}

<section class="rounded-xl border border-line-soft bg-panel p-5" aria-label="Today, midnight to midnight">
  <div class="mb-1 flex items-baseline justify-between gap-4">
    <h2 class="text-base font-medium">Today <span class="ml-1.5 font-normal text-muted">{todayLabel}</span></h2>
    <div class="flex gap-4 text-sm text-muted">
      <span class="flex items-center gap-1.5"><span class="hatch inline-block h-2.5 w-4 rounded-[3px]"></span>Scheduled</span>
      <span class="flex items-center gap-1.5"><span class="inline-block h-2.5 w-4 rounded-[3px] bg-signal"></span>Blocking</span>
    </div>
  </div>
  <DayRibbon segments={todaySegments} now={nowMin} size="lg" label="Today's blocks" />
  <div class="mt-2"><HourAxis /></div>
</section>

{#if shownKey}
  <div transition:slide={{ duration: ms(220) }}>
    <div class="mt-5 rounded-xl border border-warn/40 bg-warn/[0.06] p-5">
      <p class="flex items-center gap-2 font-medium text-warn"><Icon name="alert" size={16} />Save this unload key now</p>
      <p class="mt-1 text-sm text-muted">
        It's the only way to end this block early or unload the module, and it won't be shown again.
      </p>
      <div class="mt-4 flex items-center gap-2">
        <code class="selectable flex-1 rounded-lg border border-line bg-ink px-3 py-2 font-mono text-base tracking-wider"
          >{shownKey}</code
        >
        <button class="btn-quiet" onclick={copyKey}>
          <Icon name={copied ? "check" : "copy"} size={15} />{copied ? "Copied" : "Copy"}
        </button>
        <button class="btn-ghost" onclick={() => (shownKey = null)}>I saved it</button>
      </div>
    </div>
  </div>
{/if}

{#if s?.module_loaded}
  {#key app.blocking}
    <div in:fly={enter}>
      {#if app.blocking}
        <section class="mt-10">
          <div class="mb-3 flex items-baseline justify-between">
            <h2 class="text-lg font-medium">What's blocked</h2>
            <span class="text-sm text-muted">{s.domains.length} sites, including subdomains</span>
          </div>
          <ul class="flex flex-wrap gap-1.5">
            {#each s.domains as d (d)}
              <li class="rounded-lg border border-line-soft bg-panel px-2.5 py-1 font-mono text-sm">{d}</li>
            {/each}
          </ul>
          <div class="mt-5">
            {#if app.locked}
              <button class="btn-quiet" onclick={() => go("unlock")}><Icon name="unlock" size={16} />Unlock with a key</button>
            {:else}
              <button class="btn-quiet" disabled={busy} onclick={stopUnlocked}>
                {#if busy}<Spinner />{/if}Stop blocking
              </button>
            {/if}
          </div>
        </section>
      {:else}
        <section class="mt-5 rounded-xl border border-line-soft bg-panel p-5">
          <h2 class="mb-4 text-lg font-medium">Start a block</h2>
          <div class="flex flex-wrap items-center gap-3">
            <Segmented
              label="Length"
              value={custom ? null : minutes}
              options={presets.map((p) => ({ value: p, label: durationMinutes(p) }))}
              onchange={(p) => {
                minutes = p;
                custom = "";
              }}
            />
            <label
              class="flex h-8 items-center rounded-lg bg-raised pr-3 outline-signal transition-[outline-color] duration-150 focus-within:outline-2 focus-within:-outline-offset-1
                {custom ? 'outline-2 -outline-offset-1' : ''}"
            >
              <input
                type="number"
                min="1"
                max="10080"
                placeholder="Custom"
                bind:value={custom}
                aria-label="Custom length in minutes"
                class="h-full w-[5.5rem] bg-transparent pl-3 text-base tabular-nums placeholder:text-faint focus:outline-none [appearance:textfield]"
              />
              <span class="text-sm text-muted">min</span>
            </label>
            <button class="btn-primary h-9 px-5 max-sm:w-full sm:ml-auto" disabled={!canStart || busy} onclick={() => (confirming = true)}>
              {#if busy}<Spinner />Starting…{:else}Start blocking{/if}
            </button>
          </div>

          <p class="mt-3.5 text-sm text-muted">
            {#if s.domains.length === 0}
              There's nothing to block yet. <button class="link" onclick={() => go("sites")}>Add sites</button>
            {:else if chosen >= 1}
              Blocks {s.domains.length} sites until <span class="text-text">{endTime}</span>{holders > 0
                ? `, locked to ${holders === 1 ? "1 key holder" : `${holders} key holders`}.`
                : "."}
            {/if}
          </p>

          {#if holders === 0 && s.domains.length > 0}
            <div class="mt-4 rounded-lg border border-line-soft bg-ink/60 p-4 text-sm">
              <p class="text-text">No key holders yet, so this block can't be locked.</p>
              <p class="mt-1 text-muted">
                A key holder is someone you trust with the key that ends a block early.
                <button class="link" onclick={() => go("holders")}>Add a key holder</button>
              </p>
              <label class="mt-3 flex items-center gap-2 text-muted">
                <input type="checkbox" bind:checked={unlocked} class="accent-signal" />
                Start without a lock. The unload key is shown once.
              </label>
            </div>
          {/if}
        </section>
      {/if}
    </div>
  {/key}

  <section class="mt-10">
    <div class="mb-3 flex items-baseline justify-between">
      <h2 class="text-lg font-medium">Coming up</h2>
      <button class="link text-sm" onclick={() => go("schedule")}>Edit schedule</button>
    </div>
    {#if upcoming.length === 0}
      <p class="rounded-xl border border-dashed border-line px-5 py-5 text-base text-muted">
        No scheduled blocks. Add recurring blocks, like weekday mornings, on the
        <button class="link" onclick={() => go("schedule")}>Schedule</button> page.
      </p>
    {:else}
      <ul class="overflow-hidden rounded-xl border border-line-soft">
        {#each upcoming as o (o.block.id + o.start.getTime())}
          <li
            animate:flip={flipOpts}
            in:fly={{ y: 4, ...item }}
            class="grid grid-cols-[auto_7rem_1fr_auto] items-center gap-4 border-b border-line-soft px-4 py-3 last:border-b-0"
          >
            <span class="block h-6 w-1 rounded-full bg-signal/50"></span>
            <span class="text-muted first-letter:uppercase">{dayWord(o.start, app.now)}</span>
            <span>
              <span class="tabular-nums">{clock(o.start)} to {clock(o.end)}</span>
              {#if o.block.name}<span class="ml-2 text-muted">{o.block.name}</span>{/if}
            </span>
            <span class="text-sm text-muted tabular-nums">in {duration((o.start.getTime() - app.now.getTime()) / 1000)}</span>
          </li>
        {/each}
      </ul>
    {/if}
    {#if blocks.length > 0 && !s.scheduler_active}
      <p class="mt-3 flex items-center gap-2 text-sm text-warn">
        <Icon name="alert" size={15} />The scheduler service isn't running, so these won't start on their own.
        <button class="link" onclick={() => go("system")}>Fix it</button>
      </p>
    {/if}
  </section>
{/if}

<Dialog open={confirming} title="Start a {durationMinutes(chosen)} block?" onclose={() => (confirming = false)}>
  {#if holders > 0}
    Blocks {s?.domains.length} sites until {endTime}. It's locked: you can't end it early unless one of your key holders
    decrypts the unload key for you.
  {:else}
    Blocks {s?.domains.length} sites until {endTime}. Without a key holder it isn't locked, and the unload key is shown
    once on screen.
  {/if}
  {#snippet actions()}
    <button class="btn-ghost" onclick={() => (confirming = false)}>Cancel</button>
    <button class="btn-primary" onclick={start}>Start blocking</button>
  {/snippet}
</Dialog>
