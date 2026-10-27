<script lang="ts">
  import { hourLabel } from "../lib/time";

  let { step = 3 }: { step?: number } = $props();
  const hours = $derived(Array.from({ length: 24 / step + 1 }, (_, i) => i * step));
</script>

<div class="relative h-4 text-xs text-muted tabular-nums" aria-hidden="true">
  {#each hours as h (h)}
    <span
      class="absolute top-0 whitespace-nowrap"
      style:left="{(h / 24) * 100}%"
      style:transform={h === 0 ? "none" : h === 24 ? "translateX(-100%)" : "translateX(-50%)"}
    >
      {hourLabel(h % 24)}
    </span>
  {/each}
</div>
