/**
 * The checks against real files Ferret made (test/fixtures: an export and a backup from Ferret's own test setup), and
 * against copies of them changed in the ways that matter.
 */
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { strToU8, unzipSync, zipSync } from "fflate";
import { fingerprint, parsePublicKey, sign } from "../src/sshsig.ts";
import { snapshotsIn, verifyBackup, verifyExport } from "../src/verify.ts";

const fixtures = path.join(import.meta.dirname, "fixtures");
const EXPORT = path.join(fixtures, "export.zip");
const BACKUP = path.join(fixtures, "backup");
const exportKey = readFileSync(path.join(fixtures, "export-fingerprint.txt"), "utf8").trim();
const scratch = () => mkdtempSync(path.join(tmpdir(), "ferret-cli-"));

/** A copy of the export with one file changed (or removed, with null). */
function alteredExport(file: string, to: Uint8Array | null) {
  const files = unzipSync(new Uint8Array(readFileSync(EXPORT)));
  const name = Object.keys(files).find((n) => n.endsWith(`/${file}`))!;
  if (to) files[name] = to as Uint8Array<ArrayBuffer>;
  else delete files[name];
  const out = path.join(scratch(), "export.zip");
  writeFileSync(out, zipSync(files));
  return out;
}

describe("a thing's export", () => {
  it("is good, signed by the trusted household key", async () => {
    const r = await verifyExport(EXPORT, [{ fingerprint: exportKey, name: "Home" }]);
    assert.equal(r.verdict, "good");
    assert.equal(r.fingerprint, exportKey);
    assert.equal(r.trustedAs, "Home");
    assert.match(r.what, /^Cordless drill/);
    assert.ok(r.checked.includes("item.json"));
    assert.deepEqual(r.problems, []);
  });

  it("with no trusted key: good, but says the key wasn't compared", async () => {
    const r = await verifyExport(EXPORT, []);
    assert.equal(r.verdict, "good");
    assert.match(r.warnings.join(" "), /No trusted fingerprint/);
  });

  it("signed by a key you don't trust: untrusted", async () => {
    const r = await verifyExport(EXPORT, [{ fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }]);
    assert.equal(r.verdict, "untrusted");
    assert.equal(r.fingerprint, exportKey);
  });

  it("an unzipped folder checks the same", async () => {
    const dir = scratch();
    for (const [name, data] of Object.entries(unzipSync(new Uint8Array(readFileSync(EXPORT))))) {
      const to = path.join(dir, name);
      mkdirSync(path.dirname(to), { recursive: true });
      writeFileSync(to, data);
    }
    const root = path.join(dir, "Cordless drill");
    assert.equal((await verifyExport(root, [{ fingerprint: exportKey }])).verdict, "good");
    rmSync(dir, { recursive: true });
  });

  it("a changed, missing or added file is bad, and says which", async () => {
    const changed = await verifyExport(alteredExport("Cordless drill.md", strToU8("# Something else")), [{ fingerprint: exportKey }]);
    assert.equal(changed.verdict, "bad");
    assert.deepEqual(changed.problems, ["Cordless drill.md has changed"]);

    const files = unzipSync(new Uint8Array(readFileSync(EXPORT)));
    const photo = Object.keys(files).find((n) => n.includes("/files/") && n.endsWith(".jpg"))!;
    const missing = await verifyExport(alteredExport(photo.split("/").slice(1).join("/"), null), [{ fingerprint: exportKey }]);
    assert.deepEqual(missing.problems, [`${photo.split("/").slice(1).join("/")} is missing`]);

    files["Cordless drill/files/extra.txt"] = strToU8("hi");
    const out = path.join(scratch(), "added.zip");
    writeFileSync(out, zipSync(files));
    assert.deepEqual((await verifyExport(out, [])).problems, ["files/extra.txt was added"]);
  });

  it("re-signed by another key: untrusted, not good — and the key it carries isn't the signer", async () => {
    const files = unzipSync(new Uint8Array(readFileSync(EXPORT)));
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    files["Cordless drill/SHA256SUMS.sig"] = strToU8(await sign(pair.privateKey, raw, files["Cordless drill/SHA256SUMS"]!, "ferret-export"));
    const out = path.join(scratch(), "resigned.zip");
    writeFileSync(out, zipSync(files));
    const r = await verifyExport(out, [{ fingerprint: exportKey }]);
    assert.equal(r.verdict, "untrusted");
    assert.equal(r.fingerprint, await fingerprint(raw));
    assert.match(r.warnings.join(" "), /isn't the key that signed it/);
  });

  it("without its signature: unsigned", async () => {
    assert.equal((await verifyExport(alteredExport("SHA256SUMS.sig", null), [])).verdict, "unsigned");
  });

  it("the fingerprint of the key it carries is the household's", async () => {
    const files = unzipSync(new Uint8Array(readFileSync(EXPORT)));
    const pub = new TextDecoder().decode(files["Cordless drill/ferret-signing-key.pub"]);
    assert.equal(await fingerprint(parsePublicKey(pub)), exportKey);
  });
});

describe("a backup", () => {
  const backupKey = async () => fingerprint(parsePublicKey(readFileSync(path.join(BACKUP, "signing-key.pub"), "utf8")));
  const copy = () => {
    const dir = path.join(scratch(), "backup");
    cpSync(BACKUP, dir, { recursive: true });
    return dir;
  };

  it("is good: manifest signed, database copy and every file matching", async () => {
    const [snap] = snapshotsIn(BACKUP);
    const r = await verifyBackup(BACKUP, snap!, [{ fingerprint: await backupKey(), name: "NAS" }]);
    assert.equal(r.verdict, "good");
    assert.equal(r.trustedAs, "NAS");
    assert.deepEqual(r.problems, []);
    assert.ok(r.checked.some((c) => c.endsWith(".db.enc")));
  });

  it("a changed database copy or file is bad", async () => {
    const dir = copy();
    const [snap] = snapshotsIn(dir);
    const db = path.join(dir, "snapshots", `${snap}.db.enc`);
    const bytes = readFileSync(db);
    bytes[bytes.length - 1]! ^= 1;
    writeFileSync(db, bytes);
    const r = await verifyBackup(dir, snap!, []);
    assert.equal(r.verdict, "bad");
    assert.deepEqual(r.problems, [`${snap}.db.enc has changed`]);
  });

  it("an edited manifest no longer matches its signature", async () => {
    const dir = copy();
    const [snap] = snapshotsIn(dir);
    const file = path.join(dir, "snapshots", `${snap}.json`);
    const manifest = JSON.parse(readFileSync(file, "utf8"));
    manifest.counts.items = 999;
    writeFileSync(file, JSON.stringify(manifest, null, 1));
    const r = await verifyBackup(dir, snap!, []);
    assert.equal(r.verdict, "bad");
    assert.match(r.problems[0]!, /signature doesn't hold/);
  });

  it("a missing file is bad; signed by an untrusted key is untrusted", async () => {
    const dir = copy();
    const [snap] = snapshotsIn(dir);
    const manifest = JSON.parse(readFileSync(path.join(dir, "snapshots", `${snap}.json`), "utf8"));
    rmSync(path.join(dir, "files", manifest.files[0].key));
    assert.deepEqual((await verifyBackup(dir, snap!, [])).problems, [`files/${manifest.files[0].key} is missing`]);
    assert.equal((await verifyBackup(BACKUP, snap!, [{ fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }])).verdict, "untrusted");
  });
});
