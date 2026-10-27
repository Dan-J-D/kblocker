<script lang="ts" generics="V extends string | number">
  import { untrack } from "svelte";

  // Mutually exclusive choices in one track; the highlight slides to the
  // chosen one. Arrow keys move the choice, like radio buttons. A value
  // that matches no option (a custom entry elsewhere) hides the highlight.
  let {
    value,
    options,
    onchange,
    label,
    disabled = false,
    busy = null,
    class: cls = "",
  }: {
    value: V | null;
    options: { value: V; label: string }[];
    onchange: (v: V) => void;
    label: string;
    disabled?: boolean;
    /** Option that is being applied, shown with a pulse */
    busy?: V | null;
    class?: string;
  } = $props();

  let buttons: HTMLButtonElement[] = $state([]);
  let pill = $state({ x: 0, w: 0 });
  let placed = $state(false);

  const index = $derived(options.findIndex((o) => o.value === value));

  function place() {
    const b = buttons[index];
    if (!b) return;
    pill = { x: b.offsetLeft, w: b.offsetWidth };
    if (!placed) requestAnimationFrame(() => (placed = true));
  }

  $effect(() => {
    void index;
    void options.length;
    untrack(place);
    const ro = new ResizeObserver(place);
    for (const b of buttons) if (b) ro.observe(b);
    return () => ro.disconnect();
  });

  function pick(i: number) {
    const o = options[i];
    if (o && o.value !== value) onchange(o.value);
  }

  function onkeydown(e: KeyboardEvent) {
    const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!step || disabled) return;
    e.preventDefault();
    const i = ((index < 0 ? 0 : index) + step + options.length) % options.length;
    pick(i);
    buttons[i]?.focus();
  }
</script>

<div
  class="relative inline-flex gap-0.5 rounded-[10px] bg-raised p-0.5 {cls}"
  role="radiogroup"
  aria-label={label}
  tabindex="-1"
  {onkeydown}
>
  <span
    aria-hidden="true"
    class="pointer-events-none absolute top-0.5 bottom-0.5 left-0 rounded-lg bg-signal-deep shadow-sm shadow-black/20
      {placed ? 'transition-[translate,width] duration-[380ms] ease-[var(--ease-out)]' : ''} {index < 0 ? 'opacity-0' : ''}"
    style="translate: {pill.x}px 0; width: {pill.w}px"
  ></span>
  {#each options as o, i (o.value)}
    {@const on = i === index}
    <button
      bind:this={buttons[i]}
      type="button"
      role="radio"
      aria-checked={on}
      tabindex={on || (index < 0 && i === 0) ? 0 : -1}
      {disabled}
      class="relative flex h-7 items-center justify-center rounded-lg px-3 text-base whitespace-nowrap tabular-nums
        transition-[color,transform] duration-[380ms] ease-[var(--ease-out)] active:scale-[0.97] disabled:cursor-not-allowed
        {on ? 'text-white' : 'text-muted hover:text-text'} {busy === o.value ? 'animate-pulse' : ''}"
      onclick={() => pick(i)}
    >
      {o.label}
    </button>
  {/each}
</div>
