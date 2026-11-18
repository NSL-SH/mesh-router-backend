import { describe, it, before, after } from "mocha";
import { expect } from "chai";
import https from "https";
import { AddressInfo } from "net";
import forge from "node-forge";
import { initializeCA, signCSR } from "../services/CertificateAuthority.js";
import { validateRoute } from "../services/RouteValidator.js";

// The validator must trust the CA the backend signs with, as it is when a route is
// validated. It used to read the CA file at import, before initializeCA() generated a
// missing one, and then rejected every mesh-signed route until a second restart.
describe("route validation against the mesh CA", () => {
  let server: https.Server;
  let port: number;

  before(async function () {
    this.timeout(30000); // RSA key generation
    await initializeCA();
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;
    csr.setSubject([{ name: "commonName", value: "mesh-ca-route-test" }]);
    csr.sign(keys.privateKey);
    const { certificate } = await signCSR(forge.pki.certificationRequestToPem(csr), "mesh-ca-route-test", "127.0.0.1");
    server = https.createServer({ cert: certificate, key: forge.pki.privateKeyToPem(keys.privateKey) }, (_req, res) => res.end());
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  after(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("accepts an https agent route whose certificate the backend's CA signed", async () => {
    const result = await validateRoute({ ip: "127.0.0.1", port, priority: 1, source: "agent", scheme: "https", type: "ip" });
    expect(result.valid, result.error).to.equal(true);
  });
});
