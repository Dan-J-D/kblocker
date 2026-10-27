<script lang="ts">
  import Icon from "./Icon.svelte";

  let { url }: { url: string } = $props();
  let copied = $state(false);

  async function copy() {
    await navigator.clipboard.writeText(url);
    copied = true;
    setTimeout(() => (copied = false), 1600);
  }
</script>

<span class="inline-flex max-w-full items-center gap-1 align-middle">
  <code class="selectable truncate rounded-md border border-line-soft bg-ink px-2 py-0.5 font-mono text-sm text-text">{url}</code>
  <button class="btn-ghost h-7 px-1.5" onclick={copy} aria-label="Copy link" title="Copy link">
    <Icon name={copied ? "check" : "copy"} size={14} class={copied ? "text-ok" : ""} />
  </button>
</span>
