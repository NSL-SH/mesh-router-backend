import { getRedisClient } from "../redis/redisClient.js";
import { getDomainCacheTtl } from "../configuration/config.js";

/**
 * Redis cache of a label's Firestore lookup, for GET /resolve/v2 only.
 *
 * Every resolve used to be one Firestore query: the gateways (an offline box's empty
 * answer is asked again on each request), the CF Worker's colos and every box's own
 * zone watcher (every 120 s). On a Spark project that is the daily read quota, and once
 * it is spent every Firestore-backed endpoint answers 500 until midnight Pacific
 * (staging, 2026-11-12). Unknown labels are cached too: a 404 costs a read as well.
 *
 * Only the resolve path reads through it. Availability and ownership checks keep the
 * uncached getDomain(): a stale "not found" there would hand one name to two users.
 *
 * The backend's writes drop the entry (forgetDomain); the TTL bounds the rest — a
 * mesh-dashboard edit straight in Firestore shows after at most DOMAIN_CACHE_TTL_SECONDS.
 * Redis trouble never fails a resolve: it falls through to Firestore.
 */

const KEY_PREFIX = "domain:";

/** What a cached lookup holds: the hit, or null for a label nobody has. */
export type CachedLookup<T> = { value: T | null };

function key(label: string): string {
  return KEY_PREFIX + label.trim().toLowerCase();
}

/** The cached lookup of `label`, or undefined on a miss (or when the cache is off). */
export async function readDomainCache<T>(label: string): Promise<CachedLookup<T> | undefined> {
  if (getDomainCacheTtl() <= 0) return undefined;
  try {
    const raw = await getRedisClient().get(key(label));
    if (raw === null) return undefined;
    return { value: JSON.parse(raw) as T | null };
  } catch (e) {
    console.warn(`[domain-cache] read ${label}: ${(e as Error).message ?? e}`);
    return undefined;
  }
}

/** Store a lookup (null = no such label) for DOMAIN_CACHE_TTL_SECONDS. */
export async function writeDomainCache<T>(label: string, value: T | null): Promise<void> {
  const ttl = getDomainCacheTtl();
  if (ttl <= 0) return;
  try {
    await getRedisClient().set(key(label), JSON.stringify(value), "EX", ttl);
  } catch (e) {
    console.warn(`[domain-cache] write ${label}: ${(e as Error).message ?? e}`);
  }
}

/** Drop the cached lookup of each label given (a write changed what resolve answers). */
export async function forgetDomain(...labels: (string | null | undefined)[]): Promise<void> {
  const keys = [...new Set(labels.filter((l): l is string => !!l && !!l.trim()).map(key))];
  if (keys.length === 0) return;
  try {
    await getRedisClient().del(...keys);
  } catch (e) {
    console.warn(`[domain-cache] forget ${keys.join(",")}: ${(e as Error).message ?? e}`);
  }
}
