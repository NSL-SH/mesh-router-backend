import { describe, it } from "mocha";
import { expect } from "chai";
import forge from "node-forge";

import { randomSerial } from "../services/CertificateAuthority.js";

// The serial's DER INTEGER content, as forge writes it into a signed certificate.
function encodedSerial(serial: string): string {
  const keys = forge.pki.rsa.generateKeyPair(512);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 60_000);
  cert.setSubject([{ name: "commonName", value: "x" }]);
  cert.setIssuer([{ name: "commonName", value: "x" }]);
  cert.sign(keys.privateKey);
  const asn1 = forge.asn1.fromDer(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
  return forge.util.bytesToHex((asn1.value[0] as any).value[1].value);
}

describe("certificate serial numbers", () => {
  it("are 15 bytes, positive, with no leading zero byte", () => {
    for (let i = 0; i < 2000; i++) {
      const serial = randomSerial();
      expect(serial).to.have.length(30);
      const first = parseInt(serial.slice(0, 2), 16);
      expect(first).to.be.within(0x01, 0x7f);
    }
  });

  it("are written to DER unchanged, i.e. minimally encoded (Go rejects anything else)", () => {
    const serial = randomSerial();
    expect(encodedSerial(serial)).to.equal(serial);
  });

  it("documents the old bug: '00' + a zero byte keeps a redundant leading zero", () => {
    expect(encodedSerial("0000" + "3c".repeat(14)).slice(0, 4)).to.equal("003c");
  });
});
