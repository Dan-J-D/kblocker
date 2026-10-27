import { cubicOut } from "svelte/easing";

// Svelte transitions don't read prefers-reduced-motion, so durations go
// through here; the CSS side is handled in global.css.
const reduced =
  typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches;

export const ms = (n: number) => (reduced ? 0 : n);
export const ease = cubicOut;

export const enter = { y: 6, duration: ms(200), easing: cubicOut };
export const item = { duration: ms(180), easing: cubicOut };
export const flipOpts = { duration: ms(220), easing: cubicOut };
