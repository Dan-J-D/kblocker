import { api, errorText, type KeyHolder, type Schedule, type Status } from "./api";

class AppState {
  status = $state<Status | null>(null);
  holders = $state<KeyHolder[]>([]);
  schedule = $state<Schedule>({ blocks: [] });
  scheduleError = $state<string | null>(null);

  /** Ticks every second so countdowns and the now-line move */
  now = $state(new Date());
  #fetchedAt = 0;

  notice = $state<{ kind: "ok" | "error"; text: string } | null>(null);
  #noticeTimer: ReturnType<typeof setTimeout> | undefined;

  /** Seconds left in the current block, counted down between polls */
  remaining = $derived.by(() => {
    if (!this.status?.enabled) return 0;
    const elapsed = (this.now.getTime() - this.#fetchedAt) / 1000;
    return Math.max(0, this.status.remaining - elapsed);
  });

  endsAt = $derived(new Date(this.#fetchedAt + (this.status?.remaining ?? 0) * 1000));

  blocking = $derived(!!this.status?.enabled && this.remaining > 0);

  /** Start and planned end of the current block (Unix seconds), from the
   *  scheduler's history; null when it isn't recording */
  span = $state<{ start: number; end: number } | null>(null);

  /** Share of the current block already behind you, 0 to 1 */
  progress = $derived.by(() => {
    if (!this.blocking || !this.span) return null;
    const total = this.span.end - this.span.start;
    return total > 0 ? Math.min(1, Math.max(0, 1 - this.remaining / total)) : null;
  });
  locked = $derived(this.blocking && !!this.status?.pgp_active);

  async refreshStatus() {
    try {
      const s = await api.status();
      this.#fetchedAt = Date.now();
      this.status = s;
      if (!s.enabled) this.span = null;
      else if (!this.span) this.refreshSpan();
    } catch (e) {
      this.flash("error", errorText(e));
    }
  }

  async refreshSpan() {
    const open = (await api.history().catch(() => [])).findLast((e) => e.outcome === "open");
    this.span = open ? { start: open.start, end: open.planned_end } : null;
  }

  async refreshHolders() {
    this.holders = await api.keyHolders().catch(() => this.holders);
  }

  async refreshSchedule() {
    try {
      this.schedule = await api.schedule();
      this.scheduleError = null;
    } catch (e) {
      this.scheduleError = errorText(e);
    }
  }

  refreshAll() {
    return Promise.all([this.refreshStatus(), this.refreshHolders(), this.refreshSchedule()]);
  }

  flash(kind: "ok" | "error", text: string) {
    this.notice = { kind, text };
    clearTimeout(this.#noticeTimer);
    this.#noticeTimer = setTimeout(() => (this.notice = null), kind === "error" ? 8000 : 4000);
  }

  /** Runs a privileged action, reports the outcome and refreshes state */
  async act<T>(fn: () => Promise<T>, done?: string): Promise<T | undefined> {
    try {
      const result = await fn();
      if (done) this.flash("ok", done);
      return result;
    } catch (e) {
      this.flash("error", errorText(e));
      return undefined;
    } finally {
      await this.refreshAll();
    }
  }

  start() {
    this.refreshAll();
    const tick = setInterval(() => (this.now = new Date()), 1000);
    const poll = setInterval(() => this.refreshStatus(), 3000);
    const slow = setInterval(() => this.refreshHolders(), 15000);
    return () => {
      clearInterval(tick);
      clearInterval(poll);
      clearInterval(slow);
    };
  }
}

export const app = new AppState();
