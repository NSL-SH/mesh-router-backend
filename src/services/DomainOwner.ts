/**
 * Who owns an `nsl-router/<ownerId>` document.
 *
 * The document id is an **opaque owner id**: whatever the caller authenticated
 * as (the service key's `;<id>` part, or a Firebase uid). Yundera's
 * orchestrator and dashboard address it as `<uid>@yundera.com`, and a box signs
 * its routes over that same id (PROVIDER_STR). So the id is not a Firebase
 * uid, and must never be handed to `getAuth().getUser()` as one — doing that is
 * why `GET /user/email` answered "No Firebase user for this id." for every
 * Yundera box.
 *
 * `ownerUid` on the document is the Firebase uid of the person who owns it.
 * It is written when a document is created and backfilled on the rest
 * (`mesh-cli backfill-owner-uid`). With several boxes per user (one document
 * per box, ids like `<pcsId>@yundera.com`) it is the only link from a box back
 * to its person, which is why it is a field and not a parsing rule.
 *
 * Until every document has it, a missing field falls back to the id with the
 * `@yundera.com` suffix removed, and an id without the suffix (a direct
 * Firebase caller) is its own uid.
 */

export const YUNDERA_OWNER_SUFFIX = "@yundera.com";

/** The Firebase uid an owner id stands for, when the document does not say. */
export function uidFromOwnerId(ownerId: string): string {
  return ownerId.endsWith(YUNDERA_OWNER_SUFFIX)
    ? ownerId.slice(0, -YUNDERA_OWNER_SUFFIX.length)
    : ownerId;
}

/** The Firebase uid that owns a document: its `ownerUid`, else derived from its id. */
export function ownerUidOf(ownerId: string, data?: { ownerUid?: string } | null): string {
  const stored = data?.ownerUid;
  return typeof stored === "string" && stored ? stored : uidFromOwnerId(ownerId);
}
