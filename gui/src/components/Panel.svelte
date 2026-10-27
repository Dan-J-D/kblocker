<script lang="ts">
  import type { Snippet } from "svelte";

  let { class: cls = "", children }: { class?: string; children: Snippet } = $props();
</script>

<div class="rounded-xl border border-line-soft bg-panel p-5 {cls}">
  {@render children()}
</div>
