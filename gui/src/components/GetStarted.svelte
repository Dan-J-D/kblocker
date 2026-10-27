<script lang="ts">
  import { slide } from "svelte/transition";
  import { app } from "../lib/store.svelte";
  import { ms, ease } from "../lib/motion";
  import Icon from "./Icon.svelte";

  type View = "schedule" | "sites" | "holders";
  let { go }: { go: (v: View) => void } = $props();

  const STORE = "kblocker.getStarted.hidden";
  let hidden = $state(read());

  function read() {
    try {
      return localStorage.getItem(STORE) === "1";
    } catch {
      return false;
    }
  }

  function hide() {
    hidden = true;
    try {
      localStorage.setItem(STORE, "1");
    } catch {}
  }

  let sites = $derived(app.status?.domains.length ?? 0);
  let steps = $derived([
    {
      view: "sites" as View,
      done: sites > 0,
      title: "Choose what to block",
      body:
        sites > 0
          ? `${sites} ${sites === 1 ? "site is" : "sites are"} on your list. Social media comes preset; add anything else that pulls you away.`
          : "Pick the sites that pull you away. Social media, video and news come as ready-made lists.",
      action: sites > 0 ? "Review sites" : "Choose sites",
    },
    {
      view: "holders" as View,
      done: app.holders.length > 0,
      title: "Give someone your key",
      body: "A friend you trust holds the key that ends a block early, so stopping takes a conversation, not a click. Optional, but it's what makes a block stick.",
      action: "Add a key holder",
    },
    {
      view: "schedule" as View,
      done: app.schedule.blocks.length > 0,
      title: "Plan your week",
      body: "Blocks can start on their own, like weekday mornings, even when this app is closed.",
      action: "Set a schedule",
    },
  ]);
  let doneCount = $derived(steps.filter((s) => s.done).length);
  let firstOpen = $derived(steps.findIndex((s) => !s.done));
</script>

{#if !hidden && doneCount < steps.length}
  <section
    class="mb-5 rounded-xl border border-signal/30 bg-panel p-5"
    aria-labelledby="get-started"
    out:slide={{ duration: ms(220), easing: ease }}
  >
    <div class="flex items-baseline justify-between gap-4">
      <h2 id="get-started" class="text-lg font-medium">
        Get started <span class="ml-1.5 text-sm font-normal text-muted tabular-nums">{doneCount} of {steps.length} done</span>
      </h2>
      <button class="btn-ghost h-7 text-sm" onclick={hide}>Hide</button>
    </div>
    <ol class="mt-3 space-y-1">
      {#each steps as step, i (step.view)}
        <li class="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg px-2 py-2.5 -mx-2 {i === firstOpen ? 'bg-ink/50' : ''}">
          <span
            class="grid size-7 shrink-0 place-items-center rounded-full text-sm font-semibold
              {step.done ? 'bg-ok/15 text-ok' : i === firstOpen ? 'bg-signal text-ink' : 'bg-raised text-muted'}"
          >
            {#if step.done}<Icon name="check" size={14} />{:else}{i + 1}{/if}
          </span>
          <div class="min-w-[14rem] flex-1">
            <p class={step.done ? "text-muted line-through decoration-muted/50" : "font-medium"}>{step.title}</p>
            {#if !step.done || i === 0}<p class="text-sm text-muted">{step.body}</p>{/if}
          </div>
          <button class="{i === firstOpen ? 'btn-primary' : 'btn-quiet'} ml-11 h-8 shrink-0 text-sm sm:ml-0" onclick={() => go(step.view)}>
            {step.action}
          </button>
        </li>
      {/each}
    </ol>
    <p class="mt-3 text-sm text-muted">Or skip ahead: pick a length below and start a block right now.</p>
  </section>
{/if}
