<script lang="ts">
  import { onMount } from "svelte";
  import { fly } from "svelte/transition";
  import { app } from "./lib/store.svelte";
  import { clock, duration } from "./lib/time";
  import { enter, ms, ease } from "./lib/motion";
  import Icon, { type IconName } from "./components/Icon.svelte";
  import Now from "./views/Now.svelte";
  import Schedule from "./views/Schedule.svelte";
  import Sites from "./views/Sites.svelte";
  import KeyHolders from "./views/KeyHolders.svelte";
  import Unlock from "./views/Unlock.svelte";
  import System from "./views/System.svelte";
  import History from "./views/History.svelte";

  type View = "now" | "schedule" | "history" | "sites" | "holders" | "unlock" | "system";

  let nav = $derived<{ id: View; label: string; icon: IconName; count?: number }[]>([
    { id: "now", label: "Now", icon: "now" },
    { id: "schedule", label: "Schedule", icon: "schedule", count: app.schedule.blocks.length || undefined },
    { id: "sites", label: "Sites", icon: "sites", count: app.status?.domains.length || undefined },
    { id: "history", label: "History", icon: "history" },
    { id: "holders", label: "Key holders", icon: "holders", count: app.holders.length || undefined },
    { id: "unlock", label: "Unlock", icon: "unlock" },
    { id: "system", label: "System", icon: "system" },
  ]);

  const views: View[] = ["now", "schedule", "sites", "history", "holders", "unlock", "system"];
  const initial = location.hash.slice(1) as View;
  let view = $state<View>(views.includes(initial) ? initial : "now");
  let main: HTMLElement;

  let statusLine = $derived(
    !app.status
      ? "Checking…"
      : !app.status.module_loaded
        ? "Module not loaded"
        : app.blocking
          ? `Blocking until ${clock(app.endsAt)}`
          : "Not blocking",
  );

  // Where the sliding highlight sits: measured, since the list has gaps
  let links: Partial<Record<View, HTMLButtonElement>> = $state({});
  let mark = $state({ top: 0, height: 0 });
  let markPlaced = $state(false);
  $effect(() => {
    const el = links[view];
    if (!el) return;
    const place = () => {
      mark = { top: el.offsetTop + (el.offsetParent as HTMLElement).offsetTop, height: el.offsetHeight };
      if (!markPlaced) requestAnimationFrame(() => (markPlaced = true));
    };
    place();
    const ro = new ResizeObserver(place);
    ro.observe(document.body);
    return () => ro.disconnect();
  });

  function go(v: View) {
    if (v === view) return;
    view = v;
    main?.scrollTo({ top: 0 });
  }

  onMount(() => app.start());
</script>

<div class="flex h-screen bg-rail">
  <!-- Full sidebar on wide windows, an icon rail on narrow ones -->
  <nav class="relative flex w-16 shrink-0 flex-col pt-3.5 pb-2 pl-2 pr-2 lg:w-56 lg:pl-3 lg:pr-2.5" aria-label="Sections">
    <div class="mb-5 flex items-center justify-center gap-2.5 lg:justify-start lg:px-1.5">
      <img src="/icon.svg" alt="kblocker" class="size-7" />
      <div class="hidden min-w-0 leading-tight lg:block">
        <p class="truncate font-semibold">kblocker</p>
        <p class="truncate text-[0.85rem] text-muted">{statusLine}</p>
      </div>
    </div>

    <!-- The highlight slides to the current page -->
    <span
      aria-hidden="true"
      class="pointer-events-none absolute right-2 left-2 rounded-lg bg-raised lg:right-2.5 lg:left-3
        {markPlaced ? 'transition-[translate,height] duration-300 ease-[var(--ease-out)]' : ''}"
      style="top: 0; translate: 0 {mark.top}px; height: {mark.height}px"
    ></span>

    {#snippet link(item: (typeof nav)[number])}
      {@const active = view === item.id}
      <button
        bind:this={links[item.id]}
        class="relative flex h-8 w-full items-center justify-center gap-2.5 rounded-lg text-left text-[0.9rem] transition-colors duration-150 lg:justify-start lg:px-2
          {active ? 'font-medium text-text' : 'text-muted hover:bg-hover/60 hover:text-text'}"
        aria-current={active ? "page" : undefined}
        title={item.label}
        onclick={() => go(item.id)}
      >
        <Icon name={item.icon} size={17} class="shrink-0 {active ? 'text-signal' : ''}" />
        <span class="sr-only min-w-0 flex-1 truncate lg:not-sr-only">{item.label}</span>
        {#if item.id === "unlock" && app.locked}
          <Icon name="lock" size={13} class="hidden text-signal lg:block" />
          <span class="absolute top-1.5 right-2 size-1.5 rounded-full bg-signal lg:hidden"></span>
        {:else if item.count !== undefined}
          <span class="hidden text-[0.75rem] text-faint tabular-nums lg:inline">{item.count}</span>
        {/if}
      </button>
    {/snippet}

    <div class="relative flex flex-col gap-px">
      {#each nav.slice(0, 4) as item (item.id)}{@render link(item)}{/each}
    </div>
    <p class="relative mt-4 mb-1 hidden px-2 text-[0.8rem] text-faint lg:block">Accountability</p>
    <div class="relative mx-auto my-2.5 h-px w-6 bg-line lg:hidden" aria-hidden="true"></div>
    <div class="relative flex flex-col gap-px">
      {#each nav.slice(4, 6) as item (item.id)}{@render link(item)}{/each}
    </div>
    <div class="flex-1"></div>
    <div class="relative mb-2 flex flex-col gap-px">
      {#each nav.slice(6) as item (item.id)}{@render link(item)}{/each}
    </div>

    <!-- Always-visible state, so every screen answers "am I blocked?" -->
    <button
      class="relative rounded-xl border border-line-soft bg-raised text-left transition-colors duration-150 hover:bg-hover max-lg:grid max-lg:h-11 max-lg:place-items-center lg:px-3 lg:py-2.5"
      title={statusLine}
      onclick={() => go("now")}
    >
      <span class="flex items-center gap-2 text-[0.85rem] {app.blocking ? 'font-medium text-text' : 'text-muted'}">
        {#if app.status && !app.status.module_loaded}
          <Icon name="alert" size={15} class="text-warn" />
        {:else if app.blocking}
          <span class="relative flex size-2 shrink-0">
            <span class="absolute inset-0 animate-ping rounded-full bg-signal/60 motion-reduce:hidden"></span>
            <span class="relative size-2 rounded-full bg-signal"></span>
          </span>
        {:else}
          <span class="size-2 shrink-0 rounded-full border border-muted"></span>
        {/if}
        <span class="hidden truncate lg:inline">{app.blocking ? (app.locked ? "Locked" : "Blocking") : statusLine}</span>
        {#if app.blocking}
          <span class="ml-auto hidden text-[0.75rem] font-normal text-muted tabular-nums lg:inline">{duration(app.remaining)} left</span>
        {/if}
      </span>
      {#if app.blocking}
        <span class="mt-2 block h-1 overflow-hidden rounded-full bg-hover max-lg:hidden" aria-hidden="true">
          <span
            class="block h-full rounded-full bg-signal transition-[width] duration-1000 ease-linear"
            style:width="{(app.progress ?? 1) * 100}%"
          ></span>
        </span>
      {/if}
    </button>
  </nav>

  <main bind:this={main} class="relative m-2 ml-0 min-w-0 flex-1 overflow-y-auto rounded-xl border border-line-soft bg-ink">
    {#key view}
      <div class="mx-auto max-w-[900px] px-5 pt-8 pb-16 md:px-8 lg:px-10 lg:pt-10 2xl:max-w-[1040px]" in:fly={enter}>
        {#if view === "now"}
          <Now {go} />
        {:else if view === "schedule"}
          <Schedule />
        {:else if view === "history"}
          <History />
        {:else if view === "sites"}
          <Sites />
        {:else if view === "holders"}
          <KeyHolders />
        {:else if view === "unlock"}
          <Unlock {go} />
        {:else}
          <System />
        {/if}
      </div>
    {/key}
  </main>

  {#if app.notice}
    {@const err = app.notice.kind === "error"}
    <div
      role="status"
      transition:fly={{ y: 12, duration: ms(200), easing: ease }}
      class="selectable fixed right-5 bottom-5 z-50 flex max-w-sm items-start gap-2.5 rounded-xl border px-4 py-3 text-sm shadow-[0_12px_32px_-8px_rgb(0_0_0/0.6)] backdrop-blur
        {err ? 'border-danger/40 bg-[#2a1517]/95 text-[#ffc2bd]' : 'border-ok/30 bg-[#11231a]/95 text-[#a8eab4]'}"
    >
      <Icon name={err ? "alert" : "check"} size={16} class="mt-px {err ? 'text-danger' : 'text-ok'}" />
      <span>{app.notice.text}</span>
    </div>
  {/if}
</div>
