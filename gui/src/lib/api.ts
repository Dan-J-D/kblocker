import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { mockInvoke } from "./mock";

export interface Status {
  module_loaded: boolean;
  ctl_installed: boolean;
  enabled: boolean;
  remaining: number;
  pgp_active: boolean;
  state_restored: boolean;
  protected_files: number;
  blocked_ips: number;
  domains: string[];
  /** Networks that are never blocked, in CIDR form */
  allowed_ips: string[];
  scheduler_active: boolean;
  /** Base URL of the key holder pages hosted by the scheduler service */
  web_url: string | null;
  /** Where the scheduler hosts them: off, this computer only, the local network, or a chosen address */
  web_mode: WebMode;
  /** Address it listens on, kept while the pages are off */
  web_host: string;
  web_port: number;
}

export type WebMode = "off" | "local" | "lan" | "custom";

export interface KeyHolder {
  fingerprint: string;
  name: string;
  user: string;
  has_cipher: boolean;
}

/** Days use JS/Go weekday numbering: 0 = Sunday */
export interface ScheduleBlock {
  id: string;
  name: string;
  days: number[];
  start: string;
  end: string;
  enabled: boolean;
}

export interface HistoryEntry {
  /** Unix seconds */
  start: number;
  end?: number;
  planned_end: number;
  locked: boolean;
  /** Name of the scheduled block that started it; absent if started by hand */
  scheduled?: string;
  outcome: "open" | "completed" | "unlocked" | "interrupted";
}

export interface Schedule {
  blocks: ScheduleBlock[];
}

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// Outside Tauri (astro dev in a plain browser) the app runs on sample data
function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return inTauri ? tauriInvoke<T>(cmd, args) : mockInvoke<T>(cmd, args);
}

export const api = {
  status: () => invoke<Status>("status"),
  keyHolders: () => invoke<KeyHolder[]>("key_holders"),
  cipherFor: (fingerprint: string) => invoke<string>("cipher_for", { fingerprint }),
  ciphers: () => invoke<Record<string, string>>("ciphers"),
  schedule: () => invoke<Schedule>("schedule"),
  history: () => invoke<HistoryEntry[]>("history"),
  enable: (minutes: number, insecure: boolean) =>
    invoke<{ key: string | null }>("enable", { minutes, insecure }),
  unblock: (key: string | null) => invoke<void>("unblock", { key }),
  unload: (key: string) => invoke<void>("unload", { key }),
  setDomains: (domains: string[], removed?: string) =>
    invoke<void>("set_domains", { domains, removed: removed ?? null }),
  setAllowedIps: (nets: string[]) => invoke<void>("set_allowed_ips", { nets }),
  reload: () => invoke<void>("reload"),
  reset: (history: boolean, keyHolders: boolean) => invoke<void>("reset", { history, keyHolders }),
  setWebPages: (mode: WebMode, bind?: string, port?: number) =>
    invoke<void>("set_web_pages", { mode, bind: bind ?? null, port: port ?? null }),
  saveSchedule: (schedule: Schedule) => invoke<void>("save_schedule", { schedule }),
  addKeyHolder: (publicKey: string, name: string) =>
    invoke<void>("add_key_holder", { publicKey, name }),
  removeKeyHolder: (fingerprint: string) => invoke<void>("remove_key_holder", { fingerprint }),
  readTextFile: (path: string) => invoke<string>("read_text_file", { path }),
  writePrivateFile: (path: string, contents: string) =>
    invoke<void>("write_private_file", { path, contents }),
};

export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

/** File dialogs, with browser fallbacks for the sample-data preview */
export async function pickTextFile(title: string): Promise<string | null> {
  if (inTauri) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      title,
      multiple: false,
      filters: [{ name: "PGP key", extensions: ["asc", "gpg", "pub", "key", "txt"] }],
    });
    return typeof path === "string" ? api.readTextFile(path) : null;
  }
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.onchange = async () => resolve(input.files?.[0] ? await input.files[0].text() : null);
    input.click();
  });
}

export async function savePrivateFile(defaultName: string, contents: string): Promise<boolean> {
  if (inTauri) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({ title: "Save private key", defaultPath: defaultName });
    if (!path) return false;
    await api.writePrivateFile(path, contents);
    return true;
  }
  const url = URL.createObjectURL(new Blob([contents], { type: "application/pgp-keys" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: defaultName });
  a.click();
  URL.revokeObjectURL(url);
  return true;
}

