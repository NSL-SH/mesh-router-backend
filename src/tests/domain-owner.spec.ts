import { describe, it } from "mocha";
import { expect } from "chai";
import { ownerUidOf, uidFromOwnerId } from "../services/DomainOwner.js";

describe("DomainOwner", () => {
  it("strips the Yundera suffix to get the Firebase uid", () => {
    expect(uidFromOwnerId("R4nQt45b@yundera.com")).to.equal("R4nQt45b");
  });

  it("treats an id without the suffix as its own uid (direct Firebase callers)", () => {
    expect(uidFromOwnerId("R4nQt45b")).to.equal("R4nQt45b");
  });

  it("only strips a trailing suffix", () => {
    expect(uidFromOwnerId("a@yundera.com@yundera.com")).to.equal("a@yundera.com");
    expect(uidFromOwnerId("a@yundera.community")).to.equal("a@yundera.community");
  });

  it("prefers the stored ownerUid — the only link from a per-box doc to its person", () => {
    expect(ownerUidOf("pcs-123@yundera.com", { ownerUid: "R4nQt45b" })).to.equal("R4nQt45b");
    expect(ownerUidOf("R4nQt45b@yundera.com", {})).to.equal("R4nQt45b");
    expect(ownerUidOf("R4nQt45b@yundera.com", { ownerUid: "" })).to.equal("R4nQt45b");
    expect(ownerUidOf("R4nQt45b@yundera.com", null)).to.equal("R4nQt45b");
  });
});
