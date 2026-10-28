// Sample data for running the UI in a plain browser (`pnpm dev`), where the
// Tauri backend isn't available. ?state=active starts mid-block; ?state=new
// is a fresh install with no key holders, schedule or history.

import type { HistoryEntry, KeyHolder, Schedule, Status } from "./api";

const params = new URLSearchParams(typeof location !== "undefined" ? location.search : "");
const startActive = params.get("state") === "active";
const fresh = params.get("state") === "new";

let endsAt = startActive ? Date.now() + 102 * 60_000 : 0;
let pgp = startActive;

let allowedIps = fresh ? [] : ["10.0.0.0/24"];
let domains = ["facebook.com", "instagram.com", "x.com", "twitter.com", "tiktok.com", "reddit.com"];

let holders: KeyHolder[] = fresh ? [] : [
  {
    fingerprint: "3F2A9C1E7B4D8A06E5C1F9B2D7A4E8C3B6F1A902",
    name: "Sam",
    user: "Sam Ortega <sam@example.org>",
    has_cipher: startActive,
  },
  {
    fingerprint: "A81D4E7C29B3F6051E8D2C7A4B9F3E6D1C5A8B70",
    name: "Priya",
    user: "Priya N <priya@example.net>",
    has_cipher: startActive,
  },
];

let schedule: Schedule = {
  blocks: fresh ? [] : [
    { id: "am", name: "Morning focus", days: [1, 2, 3, 4, 5], start: "09:00", end: "12:00", enabled: true },
    { id: "pm", name: "Afternoon focus", days: [1, 2, 3, 4, 5], start: "13:00", end: "17:00", enabled: true },
  ],
};

// Four weeks of weekday focus blocks, a few cut short, some manual evenings
function sampleHistory(): HistoryEntry[] {
  const out: HistoryEntry[] = [];
  let seed = 7;
  const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  const today = new Date();
  for (let back = 27; back >= 1; back--) {
    const day = new Date(today.getFullYear(), today.getMonth(), today.getDate() - back);
    const at = (h: number, m = 0) => Math.floor(new Date(day.getFullYear(), day.getMonth(), day.getDate(), h, m).getTime() / 1000);
    const weekday = day.getDay() >= 1 && day.getDay() <= 5;
    if (weekday) {
      for (const [name, s, e] of [["Morning focus", 9, 12], ["Afternoon focus", 13, 17]] as const) {
        if (rand() < 0.08) continue;
        const cut = rand() < 0.12;
        const end = cut ? at(s, 0) + Math.floor((e - s) * 3600 * (0.3 + rand() * 0.5)) : at(e);
        out.push({ start: at(s), end, planned_end: at(e), locked: true, scheduled: name, outcome: cut ? "unlocked" : "completed" });
      }
    }
    if (rand() < 0.35) {
      const s = at(19, Math.floor(rand() * 4) * 15);
      const len = [25, 50, 90][Math.floor(rand() * 3)] * 60;
      out.push({ start: s, end: s + len, planned_end: s + len, locked: rand() < 0.7, outcome: "completed" });
    }
  }
  return out;
}
const history = fresh ? [] : sampleHistory();

let webMode: "off" | "local" | "lan" | "custom" = "local";
let webHost = "192.168.1.20";
let webPort = 8737;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function status(): Status {
  const remaining = Math.max(0, Math.round((endsAt - Date.now()) / 1000));
  if (remaining === 0) pgp = false;
  return {
    module_loaded: params.get("state") !== "unloaded",
    ctl_installed: true,
    enabled: remaining > 0,
    remaining,
    pgp_active: pgp && remaining > 0,
    state_restored: false,
    protected_files: remaining > 0 ? 4 : 0,
    blocked_ips: 0,
    domains: [...domains],
    allowed_ips: [...allowedIps],
    scheduler_active: true,
    web_url:
      webMode === "off" ? null : `http://${{ local: "127.0.0.1", lan: "192.168.1.20", custom: webHost }[webMode]}:${webPort}`,
    web_mode: webMode,
    web_host: webMode === "custom" ? webHost : webMode === "lan" ? "0.0.0.0" : "127.0.0.1",
    web_port: webPort,
  };
}

export async function mockInvoke<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  const a = args as Record<string, any>;
  switch (cmd) {
    case "status":
      return status() as T;
    case "key_holders":
      return structuredClone(holders) as T;
    case "schedule":
      return structuredClone(schedule) as T;
    case "history": {
      const st = status();
      const open: HistoryEntry[] = st.enabled
        ? [{ start: Math.floor(Date.now() / 1000) - 600, planned_end: Math.floor(endsAt / 1000), locked: st.pgp_active, outcome: "open" }]
        : [];
      return [...history, ...open] as T;
    }
    case "ciphers":
      return Object.fromEntries(
        holders.filter((h) => h.has_cipher).map((h) => [h.fingerprint, "-----BEGIN PGP MESSAGE-----\n…\n-----END PGP MESSAGE-----"]),
      ) as T;
    case "cipher_for":
      return "-----BEGIN PGP MESSAGE-----\n\nwV4D…sample…\n-----END PGP MESSAGE-----\n" as T;
  }

  await sleep(500);
  switch (cmd) {
    case "enable":
      endsAt = Date.now() + a.minutes * 60_000;
      pgp = !a.insecure;
      holders = holders.map((h) => ({ ...h, has_cipher: pgp }));
      return { key: a.insecure ? "9f3b2c71e04a58d6b1c7e2a90f4d3b85" : null } as T;
    case "unblock":
      endsAt = 0;
      pgp = false;
      holders = holders.map((h) => ({ ...h, has_cipher: false }));
      return undefined as T;
    case "set_domains":
      domains = a.domains;
      return undefined as T;
    case "set_allowed_ips":
      allowedIps = a.nets;
      return undefined as T;
    case "save_schedule":
      schedule = JSON.parse(JSON.stringify(a.schedule));
      return undefined as T;
    case "add_key_holder":
      holders = [
        ...holders,
        { fingerprint: "C0FFEE".padEnd(40, "0"), name: a.name, user: a.name, has_cipher: false },
      ];
      return undefined as T;
    case "remove_key_holder":
      holders = holders.filter((h) => h.fingerprint !== a.fingerprint);
      return undefined as T;
    case "set_web_pages":
      webMode = a.mode;
      if (a.bind) webHost = a.bind;
      if (a.port) webPort = a.port;
      return undefined as T;
    case "reload":
    case "unload":
      return undefined as T;
  }
  throw new Error(`Not available in the preview: ${cmd}`);
}
