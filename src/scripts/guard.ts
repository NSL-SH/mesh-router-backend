/**
 * mesh-cli guard [status|fleet|lift <addr>|refresh] [--json]
 *
 * The fleet ban list (services/Guard.ts):
 *   status         quorum, trust period, fleet bans, public lists and when each was fetched
 *   fleet          the fleet bans: address, until, scenario, ban number
 *   lift <addr>    lift a fleet ban (and forget its reports and escalation)
 *   refresh        fetch the public lists now (each at most once an hour, as their terms ask)
 */
import { getFleetBans, getGuardStats, liftFleetBan, refreshPublicLists, formatCidr, parseCidr } from "../services/Guard.js";
import { hasFlag, positionals, renderTable } from "../cli/format.js";

export async function main(argv: string[]): Promise<void> {
  const [sub = "status", arg] = positionals(argv);
  const json = hasFlag(argv, "json");
  const now = Date.now();

  switch (sub) {
    case "status": {
      const stats = await getGuardStats(now);
      if (json) {
        console.log(JSON.stringify(stats, null, 2));
        return;
      }
      console.log(`fleet bans: ${stats.fleetActive} active, ${stats.fleetRemembered} lapsed (remembered for escalation)`);
      console.log(`quorum: ${stats.quorum} owners in 24 h, boxes counted after ${stats.trustDays} days\n`);
      renderTable(
        ["list", "entries", "fetched", "served"],
        stats.lists.map((l) => [l.name, String(l.entries), l.fetchedAt ?? "never", l.served ? "yes" : "no"])
      );
      return;
    }
    case "fleet": {
      const bans = Object.entries(await getFleetBans(now)).sort((a, b) => b[1].until - a[1].until);
      if (json) {
        console.log(JSON.stringify(Object.fromEntries(bans), null, 2));
        return;
      }
      if (bans.length === 0) {
        console.log("(no fleet bans)");
        return;
      }
      renderTable(
        ["address", "until", "scenario", "ban #", "active"],
        bans.map(([addr, b]) => [addr, new Date(b.until).toISOString(), b.scenario, String(b.bans), b.until > now ? "yes" : "no"])
      );
      return;
    }
    case "lift": {
      const c = parseCidr(arg);
      if (!c) {
        console.error("usage: mesh-cli guard lift <address or range>");
        process.exitCode = 2;
        return;
      }
      const addr = formatCidr(c);
      console.log((await liftFleetBan(addr)) ? `lifted ${addr}` : `${addr} had no fleet ban`);
      return;
    }
    case "refresh":
      await refreshPublicLists(now);
      console.log("done (a list fetched in the last hour is skipped)");
      return;
    default:
      console.error("usage: mesh-cli guard [status|fleet|lift <addr>|refresh] [--json]");
      process.exitCode = 2;
  }
}
