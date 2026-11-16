/**
 * Who owns an `nsl-router/<ownerId>` document, as an account of THIS backend.
 *
 * The document id is an opaque owner id: whatever the caller authenticated as.
 * Two kinds exist:
 *
 * - **A direct account** (mesh dashboard, open-source boxes): the id is a
 *   Firebase uid in this backend's own project.
 * - **An operator's id**, sent with the service key (Yundera's orchestrator:
 *   `<uid>@yundera.com`). That person's account lives in the operator's own
 *   Firebase project, never in this one, and the operator provides the email
 *   to its boxes itself (they run `EMAIL_SYNC=false`).
 *
 * `ownerUid` is the uid of the owning account in this backend's project. It is
 * written only when a Firebase user of this project creates or updates the
 * document (never from a service-key call, never from the request body), and
 * backfilled by `mesh-cli backfill-owner-uid`. An operator's document has none,
 * and no lookup ever reads its id as one of our uids.
 */

/** The uid to look up in this backend's Firebase Auth: the stored `ownerUid`, else the id itself. */
export function ownerUidOf(ownerId: string, data?: { ownerUid?: string } | null): string {
  const stored = data?.ownerUid;
  return typeof stored === "string" && stored ? stored : ownerId;
}
