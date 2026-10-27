import type { ScheduleBlock } from "./api";

export const DAY = 24 * 60;

/** Rows in Monday-first order, as weekday numbers (0 = Sunday) */
export const WEEK = [1, 2, 3, 4, 5, 6, 0];
export const DAY_SHORT = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
export const DAY_LONG = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

export function toMin(hhmm: string): number {
  const [h, m] = hhmm.split(":").map(Number);
  return h * 60 + m;
}

export function fromMin(min: number): string {
  const m = ((min % DAY) + DAY) % DAY;
  return `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
}

export function blockLength(b: ScheduleBlock): number {
  const len = toMin(b.end) - toMin(b.start);
  return len > 0 ? len : len + DAY;
}

export interface Segment {
  block: ScheduleBlock;
  /** Minutes from midnight on the row's day */
  start: number;
  end: number;
  /** This piece continues from the previous day */
  carried: boolean;
}

/** Pieces of each block that fall on a weekday, including overnight spill */
export function segmentsForDay(blocks: ScheduleBlock[], weekday: number): Segment[] {
  const prev = (weekday + 6) % 7;
  const out: Segment[] = [];
  for (const block of blocks) {
    const s = toMin(block.start);
    const e = s + blockLength(block);
    if (block.days.includes(weekday)) {
      out.push({ block, start: s, end: Math.min(e, DAY), carried: false });
    }
    if (e > DAY && block.days.includes(prev)) {
      out.push({ block, start: 0, end: e - DAY, carried: true });
    }
  }
  return out.sort((a, b) => a.start - b.start);
}

export interface Occurrence {
  block: ScheduleBlock;
  start: Date;
  end: Date;
}

function occurrencesAround(blocks: ScheduleBlock[], from: Date, days: number): Occurrence[] {
  const out: Occurrence[] = [];
  for (let offset = -1; offset <= days; offset++) {
    const day = new Date(from.getFullYear(), from.getMonth(), from.getDate() + offset);
    for (const block of blocks) {
      if (!block.enabled || !block.days.includes(day.getDay())) continue;
      const s = toMin(block.start);
      const start = new Date(day.getFullYear(), day.getMonth(), day.getDate(), Math.floor(s / 60), s % 60);
      const end = new Date(start.getTime() + blockLength(block) * 60_000);
      out.push({ block, start, end });
    }
  }
  return out.sort((a, b) => a.start.getTime() - b.start.getTime());
}

/** The open window that ends last, matching what the scheduler picks */
export function activeOccurrence(blocks: ScheduleBlock[], now = new Date()): Occurrence | null {
  let best: Occurrence | null = null;
  for (const o of occurrencesAround(blocks, now, 0)) {
    if (o.start <= now && now < o.end && (!best || o.end > best.end)) best = o;
  }
  return best;
}

export function nextOccurrence(blocks: ScheduleBlock[], now = new Date()): Occurrence | null {
  return occurrencesAround(blocks, now, 7).find((o) => o.start > now) ?? null;
}

export function minutesSinceMidnight(d = new Date()): number {
  return d.getHours() * 60 + d.getMinutes() + d.getSeconds() / 60;
}

// ---- Formatting ----

const clockFmt = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const hourFmt = new Intl.DateTimeFormat(undefined, { hour: "numeric" });

export function clock(d: Date): string {
  return clockFmt.format(d);
}

export function clockHHMM(hhmm: string): string {
  const m = toMin(hhmm);
  return clock(new Date(2000, 0, 1, Math.floor(m / 60), m % 60));
}

export function hourLabel(h: number): string {
  return hourFmt.format(new Date(2000, 0, 1, h)).replace(/\s?([AP])M/i, (_, x) => x.toLowerCase());
}

/** "1h 42m", or with seconds under ten minutes so the end feels close */
export function duration(secs: number): string {
  secs = Math.max(0, Math.round(secs));
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return m ? `${h}h ${m}m` : `${h}h`;
  if (m >= 10) return `${m}m`;
  if (m > 0) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${s}s`;
}

export function durationMinutes(min: number): string {
  return duration(min * 60);
}

export function formatDays(days: number[]): string {
  const set = new Set(days);
  if (set.size === 7) return "Every day";
  if (set.size === 5 && [1, 2, 3, 4, 5].every((d) => set.has(d))) return "Weekdays";
  if (set.size === 2 && set.has(0) && set.has(6)) return "Weekends";
  return WEEK.filter((d) => set.has(d)).map((d) => DAY_SHORT[d]).join(", ");
}

/** "today", "tomorrow" or a weekday name, relative to now */
export function dayWord(d: Date, now = new Date()): string {
  const a = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const b = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const diff = Math.round((b - a) / 86_400_000);
  if (diff === 0) return "today";
  if (diff === 1) return "tomorrow";
  return DAY_LONG[d.getDay()];
}
