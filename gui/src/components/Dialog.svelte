<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    open: boolean;
    title: string;
    children: Snippet;
    actions: Snippet;
    onclose: () => void;
  }

  let { open, title, children, actions, onclose }: Props = $props();
  let el: HTMLDialogElement;

  $effect(() => {
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  });
</script>

<dialog
  bind:this={el}
  {onclose}
  class="m-auto w-[min(460px,calc(100vw-32px))] rounded-2xl border border-line bg-panel p-0 text-text shadow-[0_24px_60px_-12px_rgb(0_0_0/0.8)] backdrop:bg-black/60 backdrop:backdrop-blur-[2px]"
>
  <div class="p-6">
    <h2 class="text-lg font-semibold">{title}</h2>
    <div class="mt-2 text-base leading-relaxed text-muted">{@render children()}</div>
  </div>
  <div class="flex justify-end gap-2 border-t border-line-soft bg-ink/40 px-6 py-3.5">
    {@render actions()}
  </div>
</dialog>
