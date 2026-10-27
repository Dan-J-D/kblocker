<script lang="ts">
  import { app } from "../lib/store.svelte";
  import { api, type Schedule, type ScheduleBlock } from "../lib/api";
  import {
    blockLength,
    clockHHMM,
    durationMinutes,
    formatDays,
    fromMin,
    minutesSinceMidnight,
    segmentsForDay,
    toMin,
    DAY,
    DAY_LONG,
    DAY_SHORT,
    WEEK,
  } from "../lib/time";
  import { fly, slide } from "svelte/transition";
  import { flip } from "svelte/animate";
  import { flipOpts, item, ms, ease } from "../lib/motion";
  import DayRibbon, { type RibbonSegment } from "../components/DayRibbon.svelte";
  import HourAxis from "../components/HourAxis.svelte";
  import Icon from "../components/Icon.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import Spinner from "../components/Spinner.svelte";

  const clone = (s: Schedule): Schedule => JSON.parse(JSON.stringify(s));

  let base = $state(JSON.stringify(app.schedule));
  let draft = $state<Schedule>(clone(app.schedule));
  let selectedId = $state<string | null>(null);
  let saving = $state(false);

  let dirty = $derived(JSON.stringify(draft) !== base);
  let readOnly = $derived(app.blocking);
  let selected = $derived(draft.blocks.find((b) => b.id === selectedId) ?? null);

  // Pick up changes from disk while there's nothing unsaved to lose
  $effect(() => {
    const current = JSON.stringify(app.schedule);
    if (current !== base && !dirty) {
      draft = JSON.parse(current);
      base = current;
    }
  });

  let weeklyMinutes = $derived(
    draft.blocks.filter((b) => b.enabled).reduce((sum, b) => sum + blockLength(b) * b.days.length, 0),
  );

  function newId() {
    return Math.random().toString(36).slice(2, 10);
  }

  function rowSegments(weekday: number): RibbonSegment[] {
    return segmentsForDay(draft.blocks, weekday).map((seg) => ({
      key: `${seg.block.id}${seg.carried ? "c" : ""}`,
      id: seg.block.id,
      start: seg.start,
      end: seg.end,
      kind: "scheduled",
      label: seg.carried ? "" : seg.block.name,
      selected: seg.block.id === selectedId,
      muted: !seg.block.enabled,
      title: `${seg.block.name || "Block"}: ${clockHHMM(seg.block.start)} to ${clockHHMM(seg.block.end)}`,
    }));
  }

  function create(days: number[], start: number, end: number) {
    if (readOnly) return;
    const block: ScheduleBlock = {
      id: newId(),
      name: "",
      days,
      start: fromMin(start),
      end: fromMin(end),
      enabled: true,
    };
    draft.blocks.push(block);
    selectedId = block.id;
  }

  // Dragging over the week grid selects a box: the rows it covers are the
  // days, its horizontal extent is the time on each of them
  const SNAP = 15;
  let grid: HTMLDivElement;
  let sweep = $state<{ fromRow: number; toRow: number; from: number; to: number } | null>(null);

  let sweepBox = $derived(
    sweep
      ? {
          top: Math.min(sweep.fromRow, sweep.toRow),
          bottom: Math.max(sweep.fromRow, sweep.toRow),
          start: Math.min(sweep.from, sweep.to),
          end: Math.max(sweep.from, sweep.to),
        }
      : null,
  );

  function rowPreview(row: number) {
    const b = sweepBox;
    return b && row >= b.top && row <= b.bottom && b.end > b.start ? { start: b.start, end: b.end } : null;
  }

  function sweepStart(row: number, minute: number) {
    sweep = { fromRow: row, toRow: row, from: minute, to: minute };
    window.addEventListener("pointermove", sweepMove);
    window.addEventListener("pointerup", sweepEnd);
    window.addEventListener("pointercancel", sweepStop);
  }

  function sweepMove(e: PointerEvent) {
    if (!sweep) return;
    const tracks = [...grid.querySelectorAll<HTMLElement>("[data-track]")].map((t) => t.getBoundingClientRect());
    // Nearest row to the pointer, so the gaps between rows don't flicker
    let row = 0;
    tracks.forEach((r, i) => {
      if (Math.abs(e.clientY - (r.top + r.bottom) / 2) < Math.abs(e.clientY - (tracks[row].top + tracks[row].bottom) / 2))
        row = i;
    });
    const r = tracks[0];
    const x = Math.min(Math.max(e.clientX - r.left, 0), r.width);
    sweep.toRow = row;
    sweep.to = Math.round(((x / r.width) * DAY) / SNAP) * SNAP;
  }

  function sweepStop() {
    sweep = null;
    window.removeEventListener("pointermove", sweepMove);
    window.removeEventListener("pointerup", sweepEnd);
    window.removeEventListener("pointercancel", sweepStop);
  }

  // Drop the window listeners if the page closes mid-drag
  $effect(() => sweepStop);

  function sweepEnd() {
    const b = sweepBox;
    sweepStop();
    if (!b) return;
    let { start, end } = b;
    // A click without a drag adds a one-hour block starting there
    if (end - start < SNAP) end = Math.min(start + 60, DAY);
    if (end - start < SNAP) return;
    const days = WEEK.slice(b.top, b.bottom + 1);
    create([...days].sort(), start, end);
  }

  function useWorkday() {
    const days = [1, 2, 3, 4, 5];
    draft.blocks.push(
      { id: newId(), name: "Morning focus", days: [...days], start: "09:00", end: "12:00", enabled: true },
      { id: newId(), name: "Afternoon focus", days: [...days], start: "13:00", end: "17:00", enabled: true },
    );
  }

  function toggleDay(b: ScheduleBlock, d: number) {
    if (b.days.includes(d)) {
      if (b.days.length > 1) b.days = b.days.filter((x) => x !== d);
    } else {
      b.days = [...b.days, d].sort();
    }
  }

  function remove(id: string) {
    draft.blocks = draft.blocks.filter((b) => b.id !== id);
    if (selectedId === id) selectedId = null;
  }

  function discard() {
    draft = JSON.parse(base);
    selectedId = null;
  }

  async function save() {
    saving = true;
    const ok = await app.act(async () => {
      await api.saveSchedule($state.snapshot(draft));
      return true;
    }, "Schedule saved.");
    if (ok) base = JSON.stringify(draft);
    saving = false;
  }

  function onKey(e: KeyboardEvent) {
    if (e.key !== "Escape") return;
    if (sweep) sweepStop();
    else selectedId = null;
  }
</script>

<svelte:window onkeydown={onKey} />

<PageHeader title="Weekly schedule">
  Blocks start by themselves at these times and lock like any other block. Unlocking one early lifts it until the next
  scheduled block.
  {#snippet aside()}
    {#if weeklyMinutes > 0}<span class="tabular-nums">{durationMinutes(weeklyMinutes)} a week</span>{/if}
  {/snippet}
</PageHeader>

{#if readOnly}
  <p class="mb-5 flex items-center gap-2 rounded-lg border border-line-soft bg-panel px-4 py-3 text-sm text-muted">
    <Icon name="lock" size={15} />The schedule can't be changed while a block is running, so a block can't be shortened from the inside.
  </p>
{/if}
{#if app.scheduleError}
  <p class="mb-5 rounded-md border border-danger/40 px-3.5 py-2.5 text-sm text-danger selectable">{app.scheduleError}</p>
{/if}

<div
  bind:this={grid}
  class:select-none={!!sweep}
  class="grid grid-cols-[3rem_1fr] items-center gap-x-3 gap-y-1.5 rounded-xl border border-line-soft bg-panel p-4 pt-3">
  <span></span>
  <HourAxis />
  {#each WEEK as d, row (d)}
    {@const today = d === app.now.getDay()}
    <span class="flex items-center gap-1.5 text-sm {today ? 'font-medium text-text' : 'text-muted'}" title={DAY_LONG[d]}>
      {DAY_SHORT[d]}{#if today}<span class="size-1.5 rounded-full bg-signal"></span>{/if}
    </span>
    <DayRibbon
      segments={rowSegments(d)}
      now={today ? minutesSinceMidnight(app.now) : null}
      editable={!readOnly}
      label="{DAY_LONG[d]} blocks"
      onpick={(m) => sweepStart(row, m)}
      preview={rowPreview(row)}
      onselect={(id) => (selectedId = selectedId === id ? null : id)}
    />
  {/each}
</div>

{#if draft.blocks.length === 0}
  <div class="mt-5 flex items-center justify-between gap-6 rounded-xl border border-dashed border-line px-5 py-4">
    <p class="text-base text-muted">
      Drag across a day to add a block, or down across several days. Or start from a workday: weekdays 9 to 12 and 1 to 5.
    </p>
    <button class="btn-quiet shrink-0" disabled={readOnly} onclick={useWorkday}>Use workday schedule</button>
  </div>
{:else if !selected}
  <p class="mt-3 pl-[4.75rem] text-sm text-muted">
    {readOnly ? "Click a block to see its details." : "Drag across a day to add a block, or down across several days for the same hours. Click a block to edit it."}
  </p>
{/if}

{#if selected}
  {@const b = selected}
  {@const overnight = toMin(b.end) <= toMin(b.start)}
  <section
    class="mt-5 rounded-xl border border-signal/30 bg-panel p-5 shadow-[0_0_0_4px_rgb(88_166_255/0.05)]"
    aria-label="Edit block"
    transition:slide={{ duration: ms(200), easing: ease }}
  >
    <div class="grid grid-cols-[1fr_auto] gap-x-8 gap-y-4">
      <div>
        <label class="label" for="block-name">Name</label>
        <input id="block-name" class="field max-w-xs" placeholder="Focus block" bind:value={b.name} disabled={readOnly} />
      </div>
      <button class="btn-ghost self-start" onclick={() => (selectedId = null)} aria-label="Close editor">Done</button>

      <div class="col-span-2 flex flex-wrap items-end gap-x-10 gap-y-4">
        <fieldset>
          <legend class="label">Days</legend>
          <div class="flex gap-1">
            {#each WEEK as d (d)}
              <button
                type="button"
                aria-pressed={b.days.includes(d)}
                aria-label={DAY_LONG[d]}
                disabled={readOnly}
                class="h-9 w-10 rounded-lg border text-sm transition-all duration-150 active:scale-95
                  {b.days.includes(d)
                  ? 'border-signal bg-signal/15 text-text'
                  : 'border-line text-muted hover:border-muted hover:text-text'}"
                onclick={() => toggleDay(b, d)}
              >
                {DAY_SHORT[d].slice(0, 2)}
              </button>
            {/each}
          </div>
        </fieldset>

        <div class="flex items-end gap-2">
          <div>
            <label class="label" for="block-start">From</label>
            <input id="block-start" type="time" step="300" class="field w-36 tabular-nums" bind:value={b.start} disabled={readOnly} />
          </div>
          <span class="pb-1.5 text-muted">to</span>
          <div>
            <label class="label" for="block-end">Until</label>
            <input id="block-end" type="time" step="300" class="field w-36 tabular-nums" bind:value={b.end} disabled={readOnly} />
          </div>
          <span class="pb-1.5 pl-2 text-sm text-muted tabular-nums">
            {b.start === b.end ? "Start and end can't match" : durationMinutes(blockLength(b))}{overnight && b.start !== b.end
              ? ", ends the next day"
              : ""}
          </span>
        </div>
      </div>

      <div class="col-span-2 flex items-center justify-between border-t border-line-soft pt-4">
        <label class="flex items-center gap-2 text-base">
          <input type="checkbox" bind:checked={b.enabled} disabled={readOnly} class="accent-signal" />
          Active
          <span class="text-sm text-muted">Paused blocks stay on the schedule but don't start.</span>
        </label>
        <button class="btn-danger" disabled={readOnly} onclick={() => remove(b.id)}>Delete block</button>
      </div>
    </div>
  </section>
{/if}

{#if draft.blocks.length > 0}
  <section class="mt-10">
    <h2 class="mb-3 text-lg font-medium">All blocks</h2>
    <ul class="overflow-hidden rounded-xl border border-line-soft">
      {#each draft.blocks as b (b.id)}
        <li animate:flip={flipOpts} in:fly={{ y: 4, ...item }} class="border-b border-line-soft last:border-b-0">
          <button
            class="grid w-full grid-cols-[auto_9rem_11rem_1fr_auto] items-center gap-4 px-4 py-3 text-left transition-colors duration-150
              {b.enabled ? '' : 'text-muted'} {selectedId === b.id ? 'bg-signal/[0.07]' : 'hover:bg-hover'}"
            onclick={() => (selectedId = b.id)}
          >
            <span class="block h-6 w-1 rounded-full {b.enabled ? 'bg-signal/50' : 'bg-line'}"></span>
            <span>{formatDays(b.days)}</span>
            <span class="tabular-nums">{clockHHMM(b.start)} to {clockHHMM(b.end)}</span>
            <span class="truncate text-muted">{b.name}</span>
            <span class="text-sm text-muted tabular-nums">{b.enabled ? durationMinutes(blockLength(b)) : "Paused"}</span>
          </button>
        </li>
      {/each}
    </ul>
  </section>
{/if}

{#if dirty}
  <div
    class="sticky bottom-4 mt-8 flex items-center justify-between gap-4 rounded-xl border border-line bg-raised/90 px-4 py-2.5 shadow-[0_16px_40px_-12px_rgb(0_0_0/0.7)] backdrop-blur-md"
    transition:fly={{ y: 16, duration: ms(220), easing: ease }}
  >
    <span class="flex items-center gap-2 text-sm text-muted"><span class="size-1.5 rounded-full bg-warn"></span>Unsaved changes</span>
    <div class="flex gap-2">
      <button class="btn-ghost" onclick={discard} disabled={saving}>Discard</button>
      <button class="btn-primary" onclick={save} disabled={saving || readOnly || draft.blocks.some((b) => b.start === b.end)}>
        {#if saving}<Spinner />Saving…{:else}Save schedule{/if}
      </button>
    </div>
  </div>
{/if}
