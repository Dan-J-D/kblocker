<script lang="ts">
  import { onMount } from "svelte";
  import { fly } from "svelte/transition";
  import { app } from "../lib/store.svelte";
  import { api, type HistoryEntry } from "../lib/api";
  import { item } from "../lib/motion";
  import { clock, duration } from "../lib/time";
  import Icon, { type IconName } from "../components/Icon.svelte";
  import PageHeader from "../components/PageHeader.svelte";

  const DAYS = 28;
  const DAY_MS = 86_400_000;

  let entries = $state<HistoryEntry[] | null>(null);
  let hovered = $state<number | null>(null);
  let showAll = $state(false);

  onMount(() => {
    const load = () => api.history().then((h) => (entries = h)).catch(() => (entries ??= []));
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  });

  // An open block counts up to now
  const endOf = (e: HistoryEntry) => (e.end ?? Math.min(app.now.getTime() / 1000, e.planned_end)) * 1000;

  function midnight(d: Date) {
    return new Date(d.getFullYear(), d.getMonth(), d.getDate());
  }

  /** Seconds blocked on each of the last DAYS days, splitting blocks at midnight */
  let days = $derived.by(() => {
    const today = midnight(app.now);
    const out = Array.from({ length: DAYS }, (_, i) => {
      const date = new Date(today.getFullYear(), today.getMonth(), today.getDate() - (DAYS - 1 - i));
      return { date, seconds: 0, blocks: 0 };
    });
    const first = out[0].date.getTime();
    for (const e of entries ?? []) {
      const s = e.start * 1000;
      const en = endOf(e);
      for (const d of out) {
        const ds = d.date.getTime();
        const de = new Date(d.date.getFullYear(), d.date.getMonth(), d.date.getDate() + 1).getTime();
        const overlap = Math.min(en, de) - Math.max(s, ds);
        if (overlap > 0) {
          d.seconds += overlap / 1000;
          if (s >= ds && s < de) d.blocks++;
          else if (s < first && ds === first) d.blocks++;
        }
      }
    }
    return out;
  });

  function secondsSince(since: number) {
    let total = 0;
    for (const e of entries ?? []) {
      const overlap = endOf(e) - Math.max(e.start * 1000, since);
      if (overlap > 0) total += overlap / 1000;
    }
    return total;
  }

  let weekStart = $derived.by(() => {
    const t = midnight(app.now);
    return new Date(t.getFullYear(), t.getMonth(), t.getDate() - ((t.getDay() + 6) % 7)).getTime();
  });
  let thisWeek = $derived(secondsSince(weekStart));
  let last30 = $derived(secondsSince(midnight(app.now).getTime() - 29 * DAY_MS));

  /** Days in a row with any blocking, counting back from today (or yesterday if today is still empty) */
  let streak = $derived.by(() => {
    let i = days.length - 1;
    if (days[i].seconds < 60) i--;
    let n = 0;
    for (; i >= 0 && days[i].seconds >= 60; i--) n++;
    return n;
  });

  let finished = $derived((entries ?? []).filter((e) => e.outcome !== "open"));
  let completion = $derived(
    finished.length ? Math.round((finished.filter((e) => e.outcome === "completed").length / finished.length) * 100) : null,
  );

  // Clean hour ticks for the y-axis
  let scale = $derived.by(() => {
    const maxH = Math.max(1, ...days.map((d) => d.seconds / 3600));
    const step = maxH <= 4 ? 1 : maxH <= 8 ? 2 : 4;
    const top = Math.ceil(maxH / step) * step;
    return { top, ticks: Array.from({ length: top / step + 1 }, (_, i) => i * step) };
  });

  let recent = $derived([...(entries ?? [])].reverse().slice(0, showAll ? 100 : 8));

  const outcome: Record<HistoryEntry["outcome"], { label: string; icon: IconName; cls: string }> = {
    open: { label: "In progress", icon: "now", cls: "text-signal" },
    completed: { label: "Ran to the end", icon: "check", cls: "text-ok" },
    unlocked: { label: "Unlocked early", icon: "unlock", cls: "text-warn" },
    interrupted: { label: "Cut short", icon: "alert", cls: "text-muted" },
  };

  const dateFmt = new Intl.DateTimeFormat(undefined, { weekday: "short", month: "short", day: "numeric" });
  const dayNum = new Intl.DateTimeFormat(undefined, { day: "numeric" });
  const hours = (s: number) => (s >= 3600 ? `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m` : `${Math.round(s / 60)}m`);
</script>

<PageHeader title="History">
  Every block is recorded by the scheduler service, whether it was started here, from the command line or by the
  schedule.
</PageHeader>

{#if entries === null}
  <div class="h-28 animate-pulse rounded-xl bg-panel"></div>
{:else if entries.length === 0}
  <div class="rounded-xl border border-dashed border-line px-5 py-12 text-center">
    <Icon name="history" size={28} class="mx-auto text-muted/60" />
    <p class="mt-3 text-base">No blocks recorded yet</p>
    <p class="mt-1 text-sm text-muted">
      {app.status?.scheduler_active
        ? "Your first block will show up here as soon as it starts."
        : "History is recorded by the scheduler service, which isn't running. See the System page."}
    </p>
  </div>
{:else}
  <!-- Headline figures -->
  <div class="@container">
  <section class="grid grid-cols-2 overflow-hidden rounded-xl border border-line-soft bg-panel @min-[640px]:grid-cols-4">
    {#each [
      { label: "This week", value: hours(thisWeek), note: "blocked since Monday" },
      { label: "Last 30 days", value: hours(last30), note: `${(last30 / 3600 / 30).toFixed(1)}h a day on average` },
      { label: "Streak", value: `${streak} ${streak === 1 ? "day" : "days"}`, note: "in a row with a block" },
      { label: "Ran to the end", value: completion === null ? "–" : `${completion}%`, note: `of ${finished.length} blocks` },
    ] as fig, i (fig.label)}
      <div class="px-5 py-4 {i > 0 ? 'border-l border-line-soft' : ''} {i === 2 ? '@max-[640px]:border-l-0 @max-[640px]:border-t' : ''} {i === 3 ? '@max-[640px]:border-t' : ''}">
        <p class="text-sm text-muted">{fig.label}</p>
        <p class="mt-1 text-2xl leading-tight font-semibold tracking-tight whitespace-nowrap tabular-nums @min-[800px]:text-[1.75rem]">{fig.value}</p>
        <p class="mt-0.5 text-xs text-muted">{fig.note}</p>
      </div>
    {/each}
  </section>
  </div>

  <!-- Hours per day -->
  <section class="mt-5 rounded-xl border border-line-soft bg-panel p-5" aria-labelledby="per-day">
    <h2 id="per-day" class="text-base font-medium">Time blocked per day <span class="ml-1 font-normal text-muted">last 4 weeks</span></h2>

    <div class="relative mt-7 grid grid-cols-[2.25rem_1fr] gap-x-2">
      <!-- y-axis -->
      <div class="relative h-44 text-right text-xs text-muted tabular-nums" aria-hidden="true">
        {#each scale.ticks as t (t)}
          <span class="absolute right-0 -translate-y-1/2" style:bottom="{(t / scale.top) * 100}%">{t}h</span>
        {/each}
      </div>
      <div class="relative h-44">
        {#each scale.ticks as t (t)}
          <div class="absolute inset-x-0 h-px bg-line-soft" style:bottom="{(t / scale.top) * 100}%"></div>
        {/each}
        <div class="absolute inset-0 flex items-end">
          {#each days as d, i (d.date.getTime())}
            {@const isToday = i === days.length - 1}
            <button
              class="group relative flex h-full flex-1 items-end justify-center focus:outline-none"
              aria-label="{dateFmt.format(d.date)}: {hours(d.seconds)} blocked across {d.blocks} {d.blocks === 1 ? 'block' : 'blocks'}"
              onmouseenter={() => (hovered = i)}
              onmouseleave={() => (hovered = null)}
              onfocus={() => (hovered = i)}
              onblur={() => (hovered = null)}
            >
              {#if hovered === i}<span class="absolute inset-y-0 inset-x-px rounded-md bg-text/[0.04]"></span>{/if}
              <span
                class="relative w-[calc(100%-2px)] max-w-6 rounded-t-[4px] transition-[height,background-color] duration-500 ease-out motion-reduce:transition-none
                  {isToday ? 'bg-signal' : 'bg-signal/75 group-hover:bg-signal group-focus-visible:bg-signal'}"
                style:height="{(d.seconds / 3600 / scale.top) * 100}%"
              ></span>
            </button>
          {/each}
        </div>

        {#if hovered !== null}
          {@const d = days[hovered]}
          <div
            class="pointer-events-none absolute bottom-full z-10 mb-2 -translate-x-1/2 rounded-lg border border-line bg-raised px-3 py-2 text-sm whitespace-nowrap shadow-[0_8px_24px_-6px_rgb(0_0_0/0.6)]"
            style:left="clamp(4rem, {((hovered + 0.5) / DAYS) * 100}%, calc(100% - 4rem))"
          >
            <p class="text-muted">{dateFmt.format(d.date)}</p>
            <p class="font-medium tabular-nums">
              {d.seconds ? hours(d.seconds) : "Nothing blocked"}{#if d.blocks}<span class="font-normal text-muted"
                  >{" "}in {d.blocks} {d.blocks === 1 ? "block" : "blocks"}</span
                >{/if}
            </p>
          </div>
        {/if}
      </div>

      <!-- x-axis: Mondays and today -->
      <div></div>
      <div class="mt-2 flex text-xs text-muted tabular-nums" aria-hidden="true">
        {#each days as d, i (d.date.getTime())}
          <span class="flex-1 text-center {i === days.length - 1 ? 'font-medium text-text' : ''}">
            {i === days.length - 1 ? "Today" : d.date.getDay() === 1 ? dayNum.format(d.date) : ""}
          </span>
        {/each}
      </div>
    </div>
  </section>

  <!-- Recent blocks, which also serves as the chart's table view -->
  <section class="@container mt-10">
    <h2 class="mb-3 text-lg font-medium">Recent blocks</h2>
    <ul class="overflow-hidden rounded-xl border border-line-soft">
      {#each recent as e (e.start)}
        {@const o = outcome[e.outcome]}
        {@const start = new Date(e.start * 1000)}
        <li
          in:fly={{ y: 4, ...item }}
          class="grid grid-cols-[7.5rem_1fr_auto] items-center gap-x-4 gap-y-0.5 border-b border-line-soft px-4 py-3 last:border-b-0 @min-[640px]:grid-cols-[8rem_11.5rem_4.5rem_1fr_auto]"
        >
          <span class="text-muted">{dateFmt.format(start)}</span>
          <span class="whitespace-nowrap tabular-nums">{clock(start)} to {e.outcome === "open" ? "now" : clock(new Date(endOf(e)))}</span>
          <span class="hidden text-muted tabular-nums @min-[640px]:inline">{duration((endOf(e) - e.start * 1000) / 1000)}</span>
          <span class="hidden min-w-0 items-center gap-2 @min-[640px]:flex">
            <span class="truncate">{e.scheduled ?? "Started by hand"}</span>
            {#if e.locked}<Icon name="lock" size={13} class="shrink-0 text-muted" />{/if}
          </span>
          <span class="flex items-center gap-1.5 text-sm {o.cls}" title={o.label}
            ><Icon name={o.icon} size={14} /><span class="@max-[460px]:sr-only">{o.label}</span></span
          >
          <!-- Narrow: what started it goes on a second line -->
          <span class="col-span-2 col-start-2 -mt-0.5 flex min-w-0 items-center gap-2 text-sm text-muted @min-[640px]:hidden">
            <span class="truncate">{e.scheduled ?? "Started by hand"}</span>
            <span class="tabular-nums">· {duration((endOf(e) - e.start * 1000) / 1000)}</span>
            {#if e.locked}<Icon name="lock" size={12} class="shrink-0" />{/if}
          </span>
        </li>
      {/each}
    </ul>
    {#if !showAll && (entries?.length ?? 0) > 8}
      <button class="btn-ghost mt-2 text-sm" onclick={() => (showAll = true)}>Show more</button>
    {/if}
  </section>
{/if}
