<script lang="ts">
  // Initial on a tinted disc; the hue comes from the seed, so a key holder
  // keeps one colour everywhere
  let { name, seed = name, size = 36 }: { name: string; seed?: string; size?: number } = $props();
  const letter = $derived((name.replace(/^["'\s<]+/, "")[0] ?? "?").toUpperCase());
  const hue = $derived([...seed.toLowerCase()].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 7));
</script>

<span
  class="grid flex-none place-items-center rounded-full font-semibold"
  style="background: hsl({hue} 40% 26%); color: hsl({hue} 80% 86%); width: {size}px; height: {size}px; font-size: {Math.round(size * 0.42)}px"
  aria-hidden="true">{letter}</span
>
