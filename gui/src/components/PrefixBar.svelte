<script lang="ts">
  // Which part of an address a network fixes: filled cells are the network
  // prefix, empty ones the addresses it covers. One cell per bit for IPv4,
  // per hex digit for IPv6 (a partly fixed digit is half filled).
  let { prefix, v6 = false }: { prefix: number; v6?: boolean } = $props();

  const per = $derived(v6 ? 4 : 1);
  const groups = $derived(
    Array.from({ length: 4 }, (_, g) =>
      Array.from({ length: 8 }, (_, c) => {
        const fixed = prefix - (g * 8 + c) * per;
        return fixed >= per ? "full" : fixed > 0 ? "part" : "free";
      }),
    ),
  );
</script>

<span
  class="inline-flex items-center gap-1"
  role="img"
  aria-label="{prefix} of {v6 ? 128 : 32} bits fixed"
  title="/{prefix}: {prefix} of {v6 ? 128 : 32} bits fixed"
>
  {#each groups as cells, g (g)}
    <span class="flex gap-px">
      {#each cells as state, c (c)}
        <span
          class="h-3 w-[3px] rounded-[1px] transition-colors duration-200
            {state === 'full' ? 'bg-ok/80' : state === 'part' ? 'bg-ok/35' : 'bg-line'}"
        ></span>
      {/each}
    </span>
  {/each}
</span>
