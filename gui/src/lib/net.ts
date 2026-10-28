// IP/CIDR parsing for the allowlist. Mirrors the kernel: a bare address is
// a single-address network and host bits are cleared, so 10.0.0.255/24 is
// stored (and shown) as 10.0.0.0/24.

export interface Net {
  /** Normalized CIDR, as the kernel and kblockerctl report it */
  cidr: string;
  v6: boolean;
  prefix: number;
  first: string;
  last: string;
  /** Plain-language size, e.g. "256 addresses" */
  size: string;
}

const v4Re = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function v4ToBig(s: string): bigint {
  return s.split(".").reduce((n, o) => (n << 8n) | BigInt(o), 0n);
}

function bigToV4(n: bigint): string {
  return [24n, 16n, 8n, 0n].map((sh) => String((n >> sh) & 255n)).join(".");
}

/** Compressed IPv6 text from the WebView's own URL parser, or null */
function canonicalV6(s: string): string | null {
  if (!s.includes(":") || /[%[\]/]/.test(s)) return null;
  try {
    return new URL(`http://[${s}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

function v6ToBig(canon: string): bigint {
  // canonical form has no embedded IPv4 and at most one "::"
  const [head, tail] = canon.includes("::") ? canon.split("::") : [canon, null];
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  return groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
}

function bigToV6(n: bigint): string {
  const groups = [];
  for (let sh = 112n; sh >= 0n; sh -= 16n) groups.push(((n >> sh) & 0xffffn).toString(16));
  return canonicalV6(groups.join(":"))!;
}

const sup = "⁰¹²³⁴⁵⁶⁷⁸⁹";

function sizeText(bits: number): string {
  if (bits === 0) return "1 address";
  if (bits <= 32) return `${(2 ** bits).toLocaleString()} addresses`;
  return `2${[...String(bits)].map((d) => sup[+d]).join("")} addresses`;
}

/** Parse "addr" or "addr/prefix"; null if it isn't a valid IP or network */
export function parseNet(raw: string): Net | null {
  const [addr, pfx, extra] = raw.trim().split("/");
  if (extra !== undefined || !addr) return null;

  let v6: boolean;
  let value: bigint;
  if (v4Re.test(addr)) {
    v6 = false;
    value = v4ToBig(addr);
  } else {
    const canon = canonicalV6(addr);
    if (canon === null) return null;
    v6 = true;
    value = v6ToBig(canon);
  }

  const width = v6 ? 128 : 32;
  let prefix = width;
  if (pfx !== undefined) {
    if (!/^\d{1,3}$/.test(pfx) || +pfx > width) return null;
    prefix = +pfx;
  }

  const hostBits = BigInt(width - prefix);
  const all = (1n << BigInt(width)) - 1n;
  const hostMask = (1n << hostBits) - 1n;
  const first = value & (all ^ hostMask);
  const last = first | hostMask;
  const fmt = v6 ? bigToV6 : bigToV4;

  return {
    cidr: `${fmt(first)}/${prefix}`,
    v6,
    prefix,
    first: fmt(first),
    last: fmt(last),
    size: sizeText(width - prefix),
  };
}
