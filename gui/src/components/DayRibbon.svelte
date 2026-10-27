<script lang="ts" module>
  export interface RibbonSegment {
    key: string;
    start: number;
    end: number;
    kind: "scheduled" | "active" | "draft";
    label?: string;
    title?: string;
    selected?: boolean;
    muted?: boolean;
    /** Block id passed to onselect */
    id?: string;
  }
</script>

<script lang="ts">
  import { fade } from "svelte/transition";
  import { DAY, clock } from "../lib/time";
  import { ms } from "../lib/motion";

  interface Props {
    segments: RibbonSegment[];
    /** Minutes since midnight for the now-line, if this row is today */
    now?: number | null;
    size?: "lg" | "sm";
    editable?: boolean;
    label?: string;
    oncreate?: (start: number, end: number) => void;
    onselect?: (id: string) => void;
    /** Hands a press on empty track to the parent, for drags that span several rows */
    onpick?: (minute: number, e: PointerEvent) => void;
    /** Selection drawn by the parent while such a drag is in progress */
    preview?: { start: number; end: number } | null;
  }

  let {
    segments,
    now = null,
    size = "sm",
    editable = false,
    label,
    oncreate,
    onselect,
    onpick,
    preview = null,
  }: Props = $props();

  const SNAP = 15;
  let track: HTMLDivElement;
  let drag = $state<{ from: number; to: number } | null>(null);

  const pct = (m: number) => `${(m / DAY) * 100}%`;

  function minuteAt(e: PointerEvent): number {
    const r = track.getBoundingClientRect();
    const x = Math.min(Math.max(e.clientX - r.left, 0), r.width);
    return Math.round(((x / r.width) * DAY) / SNAP) * SNAP;
  }

  function down(e: PointerEvent) {
    if (!editable || e.button !== 0 || (e.target as HTMLElement).closest("[data-seg]")) return;
    const m = minuteAt(e);
    if (onpick) {
      e.preventDefault();
      onpick(m, e);
      return;
    }
    drag = { from: m, to: m };
    track.setPointerCapture(e.pointerId);
  }

  function move(e: PointerEvent) {
    if (drag) drag.to = minuteAt(e);
  }

  function up() {
    if (!drag) return;
    let a = Math.min(drag.from, drag.to);
    let b = Math.max(drag.from, drag.to);
    drag = null;
    // A click without a drag adds a one-hour block starting there
    if (b - a < SNAP) b = Math.min(a + 60, DAY);
    if (b - a >= SNAP) oncreate?.(a, b);
  }

  let draft = $derived(
    drag && drag.from !== drag.to
      ? { start: Math.min(drag.from, drag.to), end: Math.max(drag.from, drag.to) }
      : preview,
  );
</script>

<div class="relative" class:pt-7={size === "lg" && now !== null}>
{#if size === "lg" && now !== null}
  <!-- Current time, riding above the now-line -->
  <span
    class="now-glide pointer-events-none absolute top-0 -translate-x-1/2 rounded-md bg-text px-1.5 py-px text-xs font-medium text-ink tabular-nums"
    style:left="clamp(1.75rem, {pct(now)}, calc(100% - 1.75rem))"
  >
    {clock(new Date(2000, 0, 1, Math.floor(now / 60), Math.floor(now % 60)))}
  </span>
{/if}
<div
  bind:this={track}
  data-track
  class="ribbon relative w-full overflow-hidden {size === 'lg' ? 'h-16 rounded-lg bg-ink' : 'h-8 rounded-md bg-panel'}"
  class:cursor-crosshair={editable}
  role={editable ? "group" : "img"}
  aria-label={label}
  onpointerdown={down}
  onpointermove={move}
  onpointerup={up}
  onpointercancel={() => (drag = null)}
>
  <!-- Elapsed part of today -->
  {#if now !== null}
    <div class="now-glide absolute inset-y-0 left-0 bg-ink/55" style:width={pct(now)}></div>
  {/if}

  {#each segments as seg (seg.key)}
    {@const wide = seg.end - seg.start >= 100}
    <svelte:element
      this={seg.id && onselect ? "button" : "div"}
      data-seg
      type={seg.id && onselect ? "button" : undefined}
      role={seg.id && onselect ? undefined : "presentation"}
      in:fade={{ duration: ms(200) }}
      class="seg absolute flex items-center overflow-hidden px-1 text-left text-xs font-medium
        {size === 'lg' ? 'inset-y-1.5 rounded-md' : 'inset-y-1 rounded-[5px]'}
        {seg.kind === 'active'
        ? 'bg-signal text-ink shadow-[0_0_18px_-2px_rgb(88_166_255/0.55),inset_0_1px_0_rgb(255_255_255/0.35)]'
        : 'hatch text-text'}
        {seg.selected ? 'z-10 outline-2 outline-offset-1 outline-text' : ''}
        {seg.muted ? 'opacity-40 saturate-0' : ''}
        {seg.id && onselect ? 'cursor-pointer hover:brightness-125' : ''}"
      style:left={pct(seg.start)}
      style:width={pct(seg.end - seg.start)}
      title={seg.title}
      onclick={() => seg.id && onselect?.(seg.id)}
    >
      {#if wide && seg.label}<span
          class="truncate rounded-[3px] px-1 {seg.kind === 'active' ? '' : 'bg-ink/80'}">{seg.label}</span
        >{/if}
    </svelte:element>
  {/each}

  {#if draft}
    <div
      class="pointer-events-none absolute inset-y-1 rounded-[5px] border border-dashed border-signal bg-signal/20"
      style:left={pct(draft.start)}
      style:width={pct(draft.end - draft.start)}
    ></div>
  {/if}

  {#if now !== null}
    <div class="now-glide pointer-events-none absolute inset-y-0 w-px bg-text" style:left={pct(now)}>
      <span class="absolute -top-px left-1/2 size-[7px] -translate-x-1/2 rounded-full bg-text"></span>
    </div>
  {/if}
</div>
</div>

<style>
  .seg {
    transition:
      left 220ms cubic-bezier(0.2, 0.8, 0.2, 1),
      width 220ms cubic-bezier(0.2, 0.8, 0.2, 1),
      opacity 200ms,
      filter 150ms;
  }
  /* The clock ticks every second; glide between ticks instead of jumping */
  .now-glide {
    transition:
      left 1s linear,
      width 1s linear;
  }
  @media (prefers-reduced-motion: reduce) {
    .seg,
    .now-glide {
      transition: none;
    }
  }
  /* Hour gridlines, stronger every six hours */
  .ribbon {
    background-image:
      linear-gradient(to right, var(--color-line) 1px, transparent 1px),
      linear-gradient(to right, var(--color-line-soft) 1px, transparent 1px);
    background-size:
      25% 100%,
      calc(100% / 24) 100%;
    box-shadow: inset 0 0 0 1px var(--color-line-soft);
  }
</style>
