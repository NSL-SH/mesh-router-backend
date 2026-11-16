import { describe, it } from "mocha";
import { expect } from "chai";
import { ownerUidOf } from "../services/DomainOwner.js";

describe("DomainOwner", () => {
  it("uses the stored ownerUid", () => {
    expect(ownerUidOf("pcs-123", { ownerUid: "R4nQt45b" })).to.equal("R4nQt45b");
  });

  it("falls back to the id itself, a uid of this backend for a direct account", () => {
    expect(ownerUidOf("R4nQt45b", {})).to.equal("R4nQt45b");
    expect(ownerUidOf("R4nQt45b", { ownerUid: "" })).to.equal("R4nQt45b");
    expect(ownerUidOf("R4nQt45b", null)).to.equal("R4nQt45b");
  });

  it("never reinterprets an operator's id as one of our uids", () => {
    expect(ownerUidOf("R4nQt45b@yundera.com", null)).to.equal("R4nQt45b@yundera.com");
  });
});
