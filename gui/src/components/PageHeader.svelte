<script lang="ts">
  import type { Snippet } from "svelte";

  let { title, children, aside }: { title: string; children?: Snippet; aside?: Snippet } = $props();
</script>

<header class="mb-8 flex items-end justify-between gap-8">
  <div>
    <h1 class="text-[1.625rem] leading-tight font-semibold tracking-[-0.015em]">{title}</h1>
    {#if children}
      <p class="mt-1.5 max-w-[62ch] text-base leading-relaxed text-muted">{@render children()}</p>
    {/if}
  </div>
  {#if aside}<div class="shrink-0 pb-1 text-sm text-muted">{@render aside()}</div>{/if}
</header>
