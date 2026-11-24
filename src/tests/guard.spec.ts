import { describe, it, before, beforeEach, after } from "mocha";
import { expect } from "chai";
import sodium from "libsodium-wrappers";

import { getRedisClient } from "../redis/redisClient.js";
import {
  applyFleetBan,
  buildList,
  cidrOverlaps,
  cleanList,
  formatCidr,
  getFleetBans,
  getSignedList,
  isBannable,
  parseCidr,
  parseDshield,
  parsePlainList,
  parseSpamhausDrop,
  recordReport,
  refreshPublicList,
  reportKey,
  resetProtectedCache,
  PUBLIC_LIST_VALID_MS,
} from "../services/Guard.js";

process.env.SERVER_DOMAIN = process.env.SERVER_DOMAIN || "test.example.com";
process.env.REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
// A fixed clock far from now, so these keys never meet a real box's.
const T0 = Date.parse("2030-01-01T00:00:00Z");

async function clearGuardKeys(): Promise<void> {
  const redis = getRedisClient();
  const keys = await redis.keys("guard:*");
  if (keys.length) await redis.del(...keys);
}

describe("Guard addresses", () => {
  it("parses addresses and ranges canonically", () => {
    expect(formatCidr(parseCidr("8.8.8.8")!)).to.equal("8.8.8.8");
    expect(formatCidr(parseCidr("8.8.8.77/24")!)).to.equal("8.8.8.0/24");
    expect(formatCidr(parseCidr("2a01:4f8:0:0:0:0:0:1")!)).to.equal("2a01:4f8::1");
    expect(formatCidr(parseCidr("2A01:4F8::dead:beef/64")!)).to.equal("2a01:4f8::/64");
    expect(formatCidr(parseCidr("::ffff:1.2.3.4")!)).to.equal("::ffff:102:304");
    for (const bad of ["", "1.2.3", "1.2.3.4/33", "1.2.3.4/x", "2001:db8::/129", "1.2.3.4/8/9", "evil.com", 42, null]) {
      expect(parseCidr(bad), String(bad)).to.equal(null);
    }
  });

  it("counts an IPv6 report against its /64", () => {
    expect(reportKey("2a01:4f8:1:2:aaaa:bbbb:cccc:dddd")).to.equal("2a01:4f8:1:2::/64");
    expect(reportKey("8.8.8.8")).to.equal("8.8.8.8");
    expect(reportKey("8.8.8.0/24")).to.equal(null);
  });

  it("refuses reserved, private and too-wide ranges", () => {
    for (const ok of ["8.8.8.8", "1.10.16.0/20", "2a01:4f8::/32"]) {
      expect(isBannable(parseCidr(ok)!), ok).to.equal(true);
    }
    for (const bad of ["10.1.2.3", "192.168.1.0/24", "127.0.0.1", "100.64.0.1", "8.0.0.0/7", "fe80::1", "2001:db8::1", "::1", "0.0.0.0/0"]) {
      expect(isBannable(parseCidr(bad)!), bad).to.equal(false);
    }
  });

  it("detects overlap both ways", () => {
    expect(cidrOverlaps(parseCidr("8.8.8.0/24")!, parseCidr("8.8.8.8")!)).to.equal(true);
    expect(cidrOverlaps(parseCidr("8.8.8.8")!, parseCidr("8.8.8.0/24")!)).to.equal(true);
    expect(cidrOverlaps(parseCidr("8.8.9.0/24")!, parseCidr("8.8.8.8")!)).to.equal(false);
    expect(cidrOverlaps(parseCidr("8.8.8.8")!, parseCidr("2a01::1")!)).to.equal(false);
  });
});

describe("Guard public list parsers", () => {
  it("reads Spamhaus DROP JSON and skips its metadata line", () => {
    const body = '{"cidr":"1.10.16.0/20","sblid":"SBL1","rir":"apnic"}\n{"cidr":"2a14:c380:12::/48","sblid":"SBL2"}\n{"type":"metadata","records":2}\n';
    expect(parseSpamhausDrop(body)).to.deep.equal(["1.10.16.0/20", "2a14:c380:12::/48"]);
  });

  it("reads DShield's block.txt", () => {
    const body = "#\n# DShield\nStart\tEnd\tNetblock\tAttacks\n35.214.198.0\t35.214.198.255\t24\t325\tGOOGLE\tUS\tx@y\n";
    expect(parseDshield(body)).to.deep.equal(["35.214.198.0/24"]);
  });

  it("reads plain lists with comments", () => {
    expect(parsePlainList("# head\n50.16.16.211\n1.2.3.4 ; note\n\n# END 2 entries")).to.deep.equal(["50.16.16.211", "1.2.3.4"]);
  });

  it("keeps bannable, canonical, distinct entries", () => {
    expect(cleanList(["8.8.8.8", "8.8.8.8", "10.0.0.1", "garbage", "8.8.4.77/24"])).to.deep.equal(["8.8.8.8", "8.8.4.0/24"]);
  });
});

describe("Guard quorum (Redis)", function () {
  this.timeout(10_000);

  before(() => {
    process.env.GUARD_TRUST_DAYS = "30";
    process.env.GUARD_QUORUM = "3";
    process.env.GUARD_PUBLIC_LISTS = "blocklist-de";
  });

  beforeEach(async () => {
    await clearGuardKeys();
    resetProtectedCache([parseCidr("51.15.79.11")!]);
  });

  after(async () => {
    await clearGuardKeys();
    resetProtectedCache();
    delete process.env.GUARD_TRUST_DAYS;
    delete process.env.GUARD_QUORUM;
    delete process.env.GUARD_PUBLIC_LISTS;
  });

  /** A box with `days` of history at T0. */
  async function box(uid: string, days: number): Promise<void> {
    await getRedisClient().set(`guard:box:since:${uid}`, String(T0 - days * DAY));
  }

  const alert = (ip: string, at = T0 - HOUR, scenario = "crowdsecurity/ssh-bf") => ({ ip, scenario, at: new Date(at).toISOString() });

  it("bans fleet-wide once three owners report an address within 24 h", async () => {
    for (const uid of ["boxa", "boxb", "boxc"]) await box(uid, 40);
    expect((await recordReport("boxa", "owner1", [alert("8.8.8.8")], T0)).banned).to.deep.equal([]);
    expect((await recordReport("boxb", "owner2", [alert("8.8.8.8")], T0)).banned).to.deep.equal([]);
    const third = await recordReport("boxc", "owner3", [alert("8.8.8.8")], T0);
    expect(third).to.deep.equal({ accepted: 1, counted: 1, banned: ["8.8.8.8"] });
    const ban = (await getFleetBans(T0))["8.8.8.8"];
    expect(ban.until).to.equal(T0 + DAY);
    expect(ban.bans).to.equal(1);
  });

  it("never counts one owner twice, nor a box under its trust period", async () => {
    await box("boxa", 40);
    await box("boxb", 40);
    await box("young", 3);
    await recordReport("boxa", "owner1", [alert("8.8.8.8")], T0);
    await recordReport("boxb", "owner1", [alert("8.8.8.8")], T0);
    const young = await recordReport("young", "owner2", [alert("8.8.8.8")], T0);
    expect(young).to.deep.equal({ accepted: 1, counted: 0, banned: [] });
    expect(await getFleetBans(T0)).to.deep.equal({});
  });

  it("drops protected, reserved, stale, malformed and non-Hub alerts", async () => {
    await box("boxa", 40);
    const result = await recordReport("boxa", "owner1", [
      alert("51.15.79.11"),
      alert("10.0.0.5"),
      alert("8.8.8.8", T0 - 2 * DAY),
      alert("8.8.8.8", T0 - HOUR, "custom/my-scenario"),
      { ip: "nope", scenario: "crowdsecurity/ssh-bf", at: T0 / 1000 },
      "junk",
      alert("9.9.9.9"),
    ], T0);
    expect(result.accepted).to.equal(1);
  });

  it("escalates a repeat quorum and caps at 7 days", async () => {
    let now = T0;
    const expected = [1, 2, 4, 7, 7].map((d) => d * DAY);
    for (const duration of expected) {
      const ban = await applyFleetBan("8.8.8.8", "crowdsecurity/ssh-bf", now);
      expect(ban.until - now).to.equal(duration);
      now = ban.until + HOUR; // lapsed, still within memory
    }
  });

  it("keeps an active ban 24 h ahead without escalating, and forgets after 7 days lapsed", async () => {
    const first = await applyFleetBan("8.8.8.8", "crowdsecurity/ssh-bf", T0);
    const renewed = await applyFleetBan("8.8.8.8", "crowdsecurity/ssh-bf", T0 + 20 * HOUR);
    expect(renewed.until).to.equal(T0 + 44 * HOUR);
    expect(renewed.bans).to.equal(first.bans);
    const later = renewed.until + 8 * DAY;
    expect(await getFleetBans(later)).to.deep.equal({});
    expect((await applyFleetBan("8.8.8.8", "crowdsecurity/ssh-bf", later)).bans).to.equal(1);
  });

  it("serves fleet bans and fresh public lists, minus protected addresses", async () => {
    await applyFleetBan("8.8.8.8", "crowdsecurity/ssh-bf", T0);
    const fetched = await refreshPublicList("blocklist-de", T0, async () => "9.9.9.9\n51.15.79.11\n10.0.0.1\n");
    expect(fetched).to.equal(true);
    // a second fetch within the hour is skipped
    expect(await refreshPublicList("blocklist-de", T0 + 60_000, async () => "1.1.1.1\n")).to.equal(false);

    const list = await buildList(T0 + HOUR);
    expect(list.sources[0]).to.deep.equal({
      origin: "nsl-fleet",
      entries: [{ value: "8.8.8.8", until: new Date(T0 + DAY).toISOString(), scenario: "crowdsecurity/ssh-bf" }],
    });
    expect(list.sources[1].origin).to.equal("nsl-blocklist-de");
    expect(list.sources[1].values).to.deep.equal(["9.9.9.9"]);
    expect(list.sources[1].until).to.equal(new Date(T0 + PUBLIC_LIST_VALID_MS).toISOString());

    const stale = await buildList(T0 + PUBLIC_LIST_VALID_MS + 1);
    expect(stale.sources.map((s) => s.origin)).to.deep.equal(["nsl-fleet"]);
  });

  it("signs the list so a box can verify it", async () => {
    await sodium.ready;
    const signed = await getSignedList(T0);
    const ok = sodium.crypto_sign_verify_detached(
      new Uint8Array(Buffer.from(signed.sig, "base64")),
      new TextEncoder().encode(signed.payload),
      new Uint8Array(Buffer.from(signed.key, "base64")),
    );
    expect(ok).to.equal(true);
    expect(JSON.parse(signed.payload).v).to.equal(1);
  });
});
