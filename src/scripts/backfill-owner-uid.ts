/**
 * mesh-cli backfill-owner-uid [--apply] [--json]
 *
 * Write `ownerUid` (the owner's Firebase uid, services/DomainOwner.ts) on every
 * nsl-router document that has none. The value is the document id with
 * `@yundera.com` removed — exactly what `GET /user/email` derives while the
 * field is missing — and it is only written when Firebase Auth has that user,
 * so a stale or foreign document is reported, never labelled.
 *
 * Dry-run by default; `--apply` writes. Idempotent: documents that already have
 * the field are skipped. Reads the whole collection once (one read per
 * document) plus one Auth lookup per document to fix.
 */
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { initializeFb } from "../firebase/firebaseIntegration.js";
import { NSL_ROUTER_COLLECTION } from "../DataBaseDTO/DataBaseNSLRouter.js";
import { uidFromOwnerId } from "../services/DomainOwner.js";
import { hasFlag } from "../cli/format.js";

export async function main(argv: string[]): Promise<void> {
  const apply = hasFlag(argv, "apply");
  const json = hasFlag(argv, "json");
  initializeFb();

  const snap = await getFirestore().collection(NSL_ROUTER_COLLECTION).get();
  const out = { total: snap.size, alreadySet: 0, toWrite: [] as string[], written: 0, noFirebaseUser: [] as string[] };

  for (const doc of snap.docs) {
    if (doc.get("ownerUid")) { out.alreadySet++; continue; }
    const uid = uidFromOwnerId(doc.id);
    try {
      await getAuth().getUser(uid);
    } catch {
      out.noFirebaseUser.push(doc.id);
      continue;
    }
    out.toWrite.push(doc.id);
    if (apply) {
      await doc.ref.update({ ownerUid: uid });
      out.written++;
    }
    if (!json) console.log(`  ${apply ? "write" : "would write"} ${doc.id}: ownerUid=${uid}`);
  }

  if (json) {
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  for (const id of out.noFirebaseUser) console.log(`  SKIP ${id}: no Firebase user ${uidFromOwnerId(id)} — left unlabelled`);
  console.log(
    `\n${out.total} document(s): ${out.alreadySet} already set, ${out.toWrite.length} ${apply ? "written" : "to write"}, ` +
    `${out.noFirebaseUser.length} without a Firebase user` + (apply ? "" : " — dry-run, pass --apply to write"),
  );
}
