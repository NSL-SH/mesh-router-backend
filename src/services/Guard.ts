import dns from "node:dns/promises";
import net from "node:net";
import sodium from "libsodium-wrappers";
import { getRedisClient } from "../redis/redisClient.js";
import {
  getDnsGatewayIps,
  getGuardPublicLists,
  getGuardQuorum,
  getGuardSigningKey,
  getGuardTrustDays,
  getServerDomain,
  getTunnelProviders,
} from "../configuration/config.js";
import { getActiveUserIds, getRoutes } from "./Routes.js";

/**
 * NSL guard aggregator: the fleet half of the boxes' edge protection
 * (yundera-root doc/study/pcs-edge-protection-study.md §4.3).
 *
 * Each box runs CrowdSec and bans on its own. Its guard-sync (mesh-router-guard) does two
 * things with this module:
 *   - POST /guard/v1/reports: the addresses its own scenarios banned (IP, scenario, time;
 *     nothing else). An address reported by boxes of >= GUARD_QUORUM distinct owners
 *     within 24 h gets a fleet ban: 24 h, doubling on each new quorum while the last ban
 *     is under 7 days old, capped at 7 days. Reports keep an active ban at least 24 h
 *     ahead, so it lapses once they stop. A box counts only after GUARD_TRUST_DAYS of
 *     history, and only its alerts from unmodified-Hub scenarios (crowdsecurity/*): an
 *     owner has root on their box, so no single owner can ever ban anyone fleet-wide.
 *   - GET /guard/v1/list: the fleet bans plus the public lists fetched here hourly
 *     (Spamhaus DROP, DShield, abuse.ch Feodo, blocklist.de), as one Ed25519-signed
 *     document. The box pins the key the first time and imports the list into its
 *     CrowdSec under its own origins, after its own allowlists (SSO logins, the owner's).
 *
 * Never banned, whatever reports or lists say: the gateways, the tunnel providers, the
 * control plane (SERVER_DOMAIN's addresses), every active box's own IP, and the private
 * and reserved ranges.
 *
 * Redis keys:
 *   guard:box:since:{uid}   ms of the box's first report or list fetch (its history)
 *   guard:rep:{addr}        ZSET owner -> ms of its last report (24 h window)
 *   guard:fleet             HASH addr -> FleetBan JSON (kept 7 days past `until`)
 *   guard:list:{name}       public list: {fetchedAt, values}
 *   guard:fetch:{name}      lock: one fetch per list per hour, across replicas/restarts
 *   guard:rate:{uid}:{hour} report requests per box per hour
 *   guard:signing-key       generated signing key, when GUARD_SIGNING_KEY is unset
 *
 * Raw signals are only the 24 h report windows: nothing is kept longer.
 */

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** Report window, and the minimum a quorum keeps an active fleet ban ahead. */
const QUORUM_WINDOW_MS = DAY_MS;
const FLEET_BASE_MS = DAY_MS;
const FLEET_CAP_MS = 7 * DAY_MS;
/** How long a lapsed fleet ban still counts for escalation. */
const FLEET_MEMORY_MS = 7 * DAY_MS;
/** A box's history is forgotten after this long without a report or a fetch. */
const BOX_HISTORY_TTL_S = 120 * 24 * 60 * 60;
/**
 * A public list entry is served this long past the list's last successful fetch: a box
 * refreshes an imported entry about once a day, and a list we can no longer fetch drops
 * out two days later.
 */
export const PUBLIC_LIST_VALID_MS = 49 * HOUR_MS;

export const MAX_GUARD_ALERTS_PER_REPORT = 500;
export const MAX_GUARD_REPORTS_PER_HOUR = 30;
/** Entries kept from one public list (blocklist.de holds ~25 k). */
const MAX_LIST_VALUES = 100_000;
const MAX_LIST_BYTES = 20 * 1024 * 1024;

/** Unmodified Hub scenarios only: a box's own scenarios never count toward a fleet ban. */
const HUB_SCENARIO = /^crowdsecurity\/[a-z0-9][a-z0-9_.-]{0,100}$/;

export const FLEET_ORIGIN = "nsl-fleet";

// ---------------------------------------------------------------------------
// Addresses and ranges
// ---------------------------------------------------------------------------

export interface Cidr {
  family: 4 | 6;
  /** network address (host bits cleared) */
  n: bigint;
  bits: number;
}

function width(family: 4 | 6): number {
  return family === 4 ? 32 : 128;
}

function parseIPv6(s: string): bigint | null {
  let text = s;
  // an embedded IPv4 tail (::ffff:1.2.3.4) becomes its two groups
  const v4tail = text.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4tail) {
    const v4 = parseIPv4(v4tail[2]);
    if (v4 === null) return null;
    text = `${v4tail[1]}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const count = head.length + tail.length;
  if (halves.length === 1 ? count !== 8 : count > 7) return null;
  let n = 0n;
  for (const g of [...head, ...Array(8 - count).fill("0"), ...tail]) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

function parseIPv4(s: string): bigint | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = (n << 8n) | BigInt(Number(p));
  }
  return n;
}

/** An address or a range (`a.b.c.d`, `a.b.c.d/n`, `v6`, `v6/n`), host bits cleared; null if malformed. */
export function parseCidr(value: unknown): Cidr | null {
  if (typeof value !== "string" || value.length > 64) return null;
  const [addr, bitsText, extra] = value.trim().split("/");
  if (extra !== undefined) return null;
  const kind = net.isIP(addr);
  if (kind === 0) return null;
  const family = kind as 4 | 6;
  const n = family === 4 ? parseIPv4(addr) : parseIPv6(addr);
  if (n === null) return null;
  const w = width(family);
  let bits = w;
  if (bitsText !== undefined) {
    if (!/^\d{1,3}$/.test(bitsText)) return null;
    bits = Number(bitsText);
    if (bits > w) return null;
  }
  const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(w - bits);
  return { family, n: n & mask, bits };
}

function formatAddress(family: 4 | 6, n: bigint): string {
  if (family === 4) {
    return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 0xffn)).join(".");
  }
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) groups.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  // longest run of zero groups (length >= 2) becomes "::"
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== "0") { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === "0") j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return groups.join(":");
  return `${groups.slice(0, best).join(":")}::${groups.slice(best + bestLen).join(":")}`;
}

/** Canonical text: the bare address for a full-length prefix, else `net/bits`. */
export function formatCidr(c: Cidr): string {
  const addr = formatAddress(c.family, c.n);
  return c.bits === width(c.family) ? addr : `${addr}/${c.bits}`;
}

/** True when the two ranges share at least one address. */
export function cidrOverlaps(a: Cidr, b: Cidr): boolean {
  if (a.family !== b.family) return false;
  const w = width(a.family);
  const bits = Math.min(a.bits, b.bits);
  const shift = BigInt(w - bits);
  return (a.n >> shift) === (b.n >> shift);
}

const RESERVED: Cidr[] = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
  "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
  "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
  "::/127", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
].map((s) => parseCidr(s)!);

/** Prefixes wider than this are refused: no list may ban half a provider. */
const MIN_BITS = { 4: 8, 6: 16 } as const;

/** A public, reasonably narrow address or range. */
export function isBannable(c: Cidr): boolean {
  return c.bits >= MIN_BITS[c.family] && !RESERVED.some((r) => cidrOverlaps(r, c));
}

/**
 * What a report counts against: the address itself, or for IPv6 its /64 (privacy
 * addresses rotate within it, so a /128 would never reach a quorum).
 */
export function reportKey(ip: unknown): string | null {
  const c = parseCidr(ip);
  if (!c || c.bits !== width(c.family)) return null;
  if (c.family === 6) return formatCidr(parseCidr(`${formatAddress(6, c.n)}/64`)!);
  return formatCidr(c);
}

// ---------------------------------------------------------------------------
// Never banned: gateways, tunnel providers, control plane, the boxes
// ---------------------------------------------------------------------------

const PROTECTED_REFRESH_MS = 10 * 60 * 1000;
let protectedCache: { at: number; list: Cidr[] } | null = null;

async function resolveHost(host: string): Promise<string[]> {
  if (net.isIP(host)) return [host];
  try {
    return (await dns.lookup(host, { all: true })).map((a) => a.address);
  } catch {
    return [];
  }
}

/** The addresses no report or list may ban, refreshed every 10 minutes (wall clock). */
export async function getProtectedAddresses(): Promise<Cidr[]> {
  const now = Date.now();
  if (protectedCache && now - protectedCache.at < PROTECTED_REFRESH_MS) return protectedCache.list;
  const addresses = new Set<string>(getDnsGatewayIps());
  for (const url of getTunnelProviders()) {
    try {
      for (const a of await resolveHost(new URL(url).hostname.replace(/^\[|\]$/g, ""))) addresses.add(a);
    } catch {
      // a malformed provider URL is config's problem, reported where it is read
    }
  }
  try {
    for (const a of await resolveHost(getServerDomain())) addresses.add(a);
  } catch {
    // SERVER_DOMAIN unset: nothing to add
  }
  try {
    for (const uid of await getActiveUserIds()) {
      for (const route of (await getRoutes(uid)) ?? []) addresses.add(route.ip);
    }
  } catch (error) {
    console.warn("[GUARD] could not read the boxes' routes:", error);
    if (protectedCache) return protectedCache.list;
  }
  const list = [...addresses].map(parseCidr).filter((c): c is Cidr => !!c);
  protectedCache = { at: now, list };
  return list;
}

/** Tests: forget the cached protected set. */
export function resetProtectedCache(list?: Cidr[]): void {
  protectedCache = list ? { at: Date.now(), list } : null;
}

function isProtected(c: Cidr, protectedList: Cidr[]): boolean {
  return protectedList.some((p) => cidrOverlaps(p, c));
}

// ---------------------------------------------------------------------------
// Reports and the quorum
// ---------------------------------------------------------------------------

export interface FleetBan {
  /** ms epoch the ban ends */
  until: number;
  /** ms epoch of the quorum that started the current ban */
  since: number;
  /** scenario of the report that reached the quorum */
  scenario: string;
  /** bans so far within FLEET_MEMORY_MS of each other (1 = first) */
  bans: number;
}

const FLEET_KEY = "guard:fleet";

function boxSinceKey(uid: string): string {
  return `guard:box:since:${uid}`;
}

function reportsKey(addr: string): string {
  return `guard:rep:${addr}`;
}

/** Records the box's history (first seen) and returns its start, ms epoch. */
export async function touchBox(uid: string, now = Date.now()): Promise<number> {
  const redis = getRedisClient();
  const key = boxSinceKey(uid);
  await redis.set(key, String(now), "NX");
  await redis.expire(key, BOX_HISTORY_TTL_S);
  return Number(await redis.get(key)) || now;
}

/** One more report request this hour; false once the box is past its hourly allowance. */
export async function takeReportSlot(uid: string, now = Date.now()): Promise<boolean> {
  const redis = getRedisClient();
  const key = `guard:rate:${uid}:${Math.floor(now / HOUR_MS)}`;
  const n = await redis.incr(key);
  if (n === 1) await redis.expire(key, 2 * 60 * 60);
  return n <= MAX_GUARD_REPORTS_PER_HOUR;
}

function parseTime(at: unknown): number | null {
  const ms = typeof at === "number" ? at * 1000 : typeof at === "string" ? Date.parse(at) : NaN;
  return Number.isFinite(ms) ? ms : null;
}

export interface ReportResult {
  /** well-formed alerts about bannable addresses */
  accepted: number;
  /** of which counted toward a quorum (0 while the box has under GUARD_TRUST_DAYS of history) */
  counted: number;
  /** addresses whose fleet ban this report started or renewed */
  banned: string[];
}

/**
 * Records a box's report: alerts `{ip, scenario, at}` (at: ISO time or epoch seconds,
 * within the last 24 h). Malformed alerts, other scenarios, and protected or reserved
 * addresses are dropped, not rejected.
 */
export async function recordReport(uid: string, owner: string, alerts: unknown[], now = Date.now()): Promise<ReportResult> {
  const since = await touchBox(uid, now);
  const trusted = now - since >= getGuardTrustDays() * DAY_MS;
  const protectedList = await getProtectedAddresses();
  const latest = new Map<string, { at: number; scenario: string }>();
  for (const alert of alerts) {
    if (!alert || typeof alert !== "object") continue;
    const { ip, scenario, at } = alert as Record<string, unknown>;
    if (typeof scenario !== "string" || !HUB_SCENARIO.test(scenario)) continue;
    const key = reportKey(ip);
    const ms = parseTime(at);
    if (!key || ms === null || ms < now - QUORUM_WINDOW_MS || ms > now + 5 * 60 * 1000) continue;
    const c = parseCidr(key)!;
    if (!isBannable(c) || isProtected(c, protectedList)) continue;
    const seen = latest.get(key);
    if (!seen || seen.at < ms) latest.set(key, { at: Math.min(ms, now), scenario });
  }

  const result: ReportResult = { accepted: latest.size, counted: 0, banned: [] };
  if (!trusted || latest.size === 0) return result;

  const redis = getRedisClient();
  const quorum = getGuardQuorum();
  for (const [addr, { at, scenario }] of latest) {
    const key = reportsKey(addr);
    const pipeline = redis.pipeline();
    pipeline.zadd(key, "GT", at, owner);
    pipeline.zremrangebyscore(key, "-inf", now - QUORUM_WINDOW_MS);
    pipeline.zcard(key);
    pipeline.pexpire(key, QUORUM_WINDOW_MS + HOUR_MS);
    const replies = await pipeline.exec();
    result.counted++;
    const owners = Number(replies?.[2]?.[1] ?? 0);
    if (owners >= quorum) {
      await applyFleetBan(addr, scenario, now);
      result.banned.push(addr);
    }
  }
  return result;
}

/** Starts a fleet ban, escalating, or keeps an active one at least FLEET_BASE_MS ahead. */
export async function applyFleetBan(addr: string, scenario: string, now = Date.now()): Promise<FleetBan> {
  const redis = getRedisClient();
  const raw = await redis.hget(FLEET_KEY, addr);
  const prev = raw ? (JSON.parse(raw) as FleetBan) : null;
  let ban: FleetBan;
  if (prev && prev.until > now) {
    ban = { ...prev, until: Math.max(prev.until, now + FLEET_BASE_MS) };
  } else {
    const bans = prev && prev.until + FLEET_MEMORY_MS > now ? prev.bans + 1 : 1;
    const duration = Math.min(FLEET_BASE_MS * 2 ** (bans - 1), FLEET_CAP_MS);
    ban = { until: now + duration, since: now, scenario, bans };
    console.log(`[GUARD] fleet ban ${addr} for ${duration / HOUR_MS} h (${scenario}, ban #${bans})`);
  }
  await redis.hset(FLEET_KEY, addr, JSON.stringify(ban));
  invalidateList();
  return ban;
}

/** Lifts a fleet ban (admin). Its escalation memory goes with it. */
export async function liftFleetBan(addr: string): Promise<boolean> {
  const redis = getRedisClient();
  const removed = await redis.hdel(FLEET_KEY, addr);
  await redis.del(reportsKey(addr));
  invalidateList();
  return removed === 1;
}

/** Every fleet ban, active or remembered, purging those past their memory. */
export async function getFleetBans(now = Date.now()): Promise<Record<string, FleetBan>> {
  const redis = getRedisClient();
  const all = await redis.hgetall(FLEET_KEY);
  const out: Record<string, FleetBan> = {};
  const stale: string[] = [];
  for (const [addr, raw] of Object.entries(all)) {
    try {
      const ban = JSON.parse(raw) as FleetBan;
      if (ban.until + FLEET_MEMORY_MS < now) stale.push(addr);
      else out[addr] = ban;
    } catch {
      stale.push(addr);
    }
  }
  if (stale.length) await redis.hdel(FLEET_KEY, ...stale);
  return out;
}

// ---------------------------------------------------------------------------
// Public lists
// ---------------------------------------------------------------------------

interface PublicListSource {
  urls: string[];
  parse: (body: string) => string[];
  /** credit shown to owners (mesh-console); some lists require it */
  attribution: string;
}

/** One address or range per line; `#` and `;` start a comment. */
export function parsePlainList(body: string): string[] {
  const out: string[] = [];
  for (const line of body.split(/\r?\n/)) {
    const token = line.replace(/[#;].*$/, "").trim().split(/\s+/)[0];
    if (token) out.push(token);
  }
  return out;
}

/** Spamhaus DROP JSON: one object per line, `{"cidr": ...}`, then a metadata line. */
export function parseSpamhausDrop(body: string): string[] {
  const out: string[] = [];
  for (const line of body.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      if (typeof row?.cidr === "string") out.push(row.cidr);
    } catch {
      // not a record
    }
  }
  return out;
}

/** DShield block.txt: `start<TAB>end<TAB>prefix-length<TAB>...`, `#` comments, a header row. */
export function parseDshield(body: string): string[] {
  const out: string[] = [];
  for (const line of body.split(/\r?\n/)) {
    if (line.startsWith("#")) continue;
    const [start, , bits] = line.split("\t");
    if (start && bits && net.isIPv4(start) && /^\d{1,2}$/.test(bits)) out.push(`${start}/${bits}`);
  }
  return out;
}

export const PUBLIC_LIST_SOURCES: Record<string, PublicListSource> = {
  "spamhaus-drop": {
    urls: ["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"],
    parse: parseSpamhausDrop,
    attribution: "Spamhaus DROP",
  },
  dshield: {
    urls: ["https://feeds.dshield.org/block.txt"],
    parse: parseDshield,
    attribution: "DShield.org (SANS Internet Storm Center)",
  },
  feodo: {
    urls: ["https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"],
    parse: parsePlainList,
    attribution: "abuse.ch Feodo Tracker",
  },
  "blocklist-de": {
    urls: ["https://lists.blocklist.de/lists/all.txt"],
    parse: parsePlainList,
    attribution: "blocklist.de",
  },
};

interface StoredList {
  fetchedAt: number;
  values: string[];
}

function listKey(name: string): string {
  return `guard:list:${name}`;
}

/** Keeps the bannable, canonical, distinct entries of a parsed list. */
export function cleanList(values: string[]): string[] {
  const out = new Set<string>();
  for (const v of values) {
    const c = parseCidr(v);
    if (c && isBannable(c)) out.add(formatCidr(c));
    if (out.size >= MAX_LIST_VALUES) break;
  }
  return [...out];
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: { "User-Agent": `nsl-guard/1 (mesh-router-backend; ${process.env.SERVER_DOMAIN || "unknown"})` },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_LIST_BYTES) throw new Error(`over ${MAX_LIST_BYTES} bytes`);
  return text;
}

/**
 * Fetches one public list unless it was fetched in the last hour (any replica), and stores
 * it. A failed or empty fetch keeps the previous copy, which is served until
 * PUBLIC_LIST_VALID_MS after its own fetch.
 */
export async function refreshPublicList(name: string, now = Date.now(), fetcher = fetchText): Promise<boolean> {
  const source = PUBLIC_LIST_SOURCES[name];
  if (!source) return false;
  const redis = getRedisClient();
  // Spamhaus and ISC ask for at most one fetch an hour.
  if ((await redis.set(`guard:fetch:${name}`, String(now), "PX", HOUR_MS - 60_000, "NX")) !== "OK") return false;
  try {
    const parsed: string[] = [];
    for (const url of source.urls) parsed.push(...source.parse(await fetcher(url)));
    const values = cleanList(parsed);
    if (values.length === 0) throw new Error("no entries");
    const stored: StoredList = { fetchedAt: now, values };
    await redis.set(listKey(name), JSON.stringify(stored));
    invalidateList();
    console.log(`[GUARD] ${name}: ${values.length} entries`);
    return true;
  } catch (error) {
    console.warn(`[GUARD] ${name}: fetch failed, keeping the previous copy:`, (error as Error).message);
    return false;
  }
}

export async function refreshPublicLists(now = Date.now()): Promise<void> {
  for (const name of getGuardPublicLists()) await refreshPublicList(name, now);
}

async function getStoredList(name: string): Promise<StoredList | null> {
  const raw = await getRedisClient().get(listKey(name));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredList;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// The signed list
// ---------------------------------------------------------------------------

export interface GuardListEntry {
  value: string;
  until: string;
  scenario: string;
}

export interface GuardListSource {
  /** CrowdSec decision origin on the box: nsl-fleet, or nsl-<list> */
  origin: string;
  attribution?: string;
  /** default for the source's values */
  until?: string;
  scenario?: string;
  /** fleet bans: one entry each */
  entries?: GuardListEntry[];
  /** public lists: values sharing `until` and `scenario` */
  values?: string[];
}

export interface GuardList {
  v: 1;
  generatedAt: string;
  sources: GuardListSource[];
}

/** The list every box receives (the same for all), protected and reserved addresses left out. */
export async function buildList(now = Date.now()): Promise<GuardList> {
  const protectedList = await getProtectedAddresses();
  const keep = (value: string) => {
    const c = parseCidr(value);
    return !!c && isBannable(c) && !isProtected(c, protectedList);
  };
  const sources: GuardListSource[] = [];

  const entries: GuardListEntry[] = [];
  for (const [value, ban] of Object.entries(await getFleetBans(now))) {
    if (ban.until > now && keep(value)) {
      entries.push({ value, until: new Date(ban.until).toISOString(), scenario: ban.scenario });
    }
  }
  sources.push({ origin: FLEET_ORIGIN, entries });

  for (const name of getGuardPublicLists()) {
    const stored = await getStoredList(name);
    if (!stored || stored.fetchedAt + PUBLIC_LIST_VALID_MS <= now) continue;
    sources.push({
      origin: `nsl-${name}`,
      attribution: PUBLIC_LIST_SOURCES[name].attribution,
      until: new Date(stored.fetchedAt + PUBLIC_LIST_VALID_MS).toISOString(),
      scenario: name,
      values: stored.values.filter(keep),
    });
  }
  return { v: 1, generatedAt: new Date(now).toISOString(), sources };
}

export interface SignedGuardList {
  /** base64 Ed25519 public key; the box pins the first one it sees */
  key: string;
  /** base64 detached signature over `payload` (UTF-8) */
  sig: string;
  /** GuardList as JSON text: verify it before parsing */
  payload: string;
}

let signingKey: Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> | null = null;

async function getSigningKey() {
  if (!signingKey) {
    signingKey = (async () => {
      await sodium.ready;
      let secret = getGuardSigningKey();
      if (!secret) {
        const redis = getRedisClient();
        const fresh = Buffer.from(sodium.crypto_sign_keypair().privateKey).toString("base64");
        await redis.set("guard:signing-key", fresh, "NX");
        secret = (await redis.get("guard:signing-key")) ?? fresh;
      }
      const privateKey = new Uint8Array(Buffer.from(secret, "base64"));
      if (privateKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
        throw new Error("GUARD_SIGNING_KEY must be base64 of a 64-byte Ed25519 secret key");
      }
      // libsodium's secret key is seed || public key
      return { privateKey, publicKey: privateKey.slice(32) };
    })().catch((error) => {
      signingKey = null;
      throw error;
    });
  }
  return signingKey;
}

/** base64 public key of the list signature. */
export async function getGuardPublicKey(): Promise<string> {
  return Buffer.from((await getSigningKey()).publicKey).toString("base64");
}

const LIST_CACHE_MS = 60_000;
let listCache: { at: number; list: Promise<SignedGuardList> } | null = null;

function invalidateList(): void {
  listCache = null;
}

/** The signed list, rebuilt at most once a minute (and at once after a fleet ban or a list fetch). */
export async function getSignedList(now = Date.now()): Promise<SignedGuardList> {
  if (!listCache || now - listCache.at >= LIST_CACHE_MS) {
    const list = (async () => {
      const { privateKey, publicKey } = await getSigningKey();
      const payload = JSON.stringify(await buildList(now));
      const sig = sodium.crypto_sign_detached(new TextEncoder().encode(payload), privateKey);
      return {
        key: Buffer.from(publicKey).toString("base64"),
        sig: Buffer.from(sig).toString("base64"),
        payload,
      };
    })();
    listCache = { at: now, list };
    list.catch(() => {
      if (listCache?.list === list) listCache = null;
    });
  }
  return listCache.list;
}

// ---------------------------------------------------------------------------
// Background job
// ---------------------------------------------------------------------------

/** Fetches the public lists now and every 15 minutes (each one at most hourly, see refreshPublicList). */
export function startGuardLists(): void {
  const names = getGuardPublicLists();
  if (names.length === 0) {
    console.log("[GUARD] public lists: none (GUARD_PUBLIC_LISTS=none)");
    return;
  }
  console.log(`[GUARD] public lists: ${names.join(", ")}`);
  const run = () => refreshPublicLists().catch((error) => console.warn("[GUARD] list refresh failed:", error));
  setTimeout(run, 30_000).unref();
  setInterval(run, 15 * 60 * 1000).unref();
}

export interface GuardStats {
  fleetActive: number;
  fleetRemembered: number;
  lists: { name: string; entries: number; fetchedAt: string | null; served: boolean }[];
  quorum: number;
  trustDays: number;
}

export async function getGuardStats(now = Date.now()): Promise<GuardStats> {
  const fleet = Object.values(await getFleetBans(now));
  const lists = [];
  for (const name of getGuardPublicLists()) {
    const stored = await getStoredList(name);
    lists.push({
      name,
      entries: stored?.values.length ?? 0,
      fetchedAt: stored ? new Date(stored.fetchedAt).toISOString() : null,
      served: !!stored && stored.fetchedAt + PUBLIC_LIST_VALID_MS > now,
    });
  }
  return {
    fleetActive: fleet.filter((b) => b.until > now).length,
    fleetRemembered: fleet.filter((b) => b.until <= now).length,
    lists,
    quorum: getGuardQuorum(),
    trustDays: getGuardTrustDays(),
  };
}
