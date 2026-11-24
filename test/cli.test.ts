/** The `ferret` command itself: trust in the config file, exit codes, and export from a (stand-in) Ferret. */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const fixtures = path.join(import.meta.dirname, "fixtures");
const cli = path.join(import.meta.dirname, "..", "src", "cli.ts");
const exportKey = readFileSync(path.join(fixtures, "export-fingerprint.txt"), "utf8").trim();

function ferret(args: string[], env: Record<string, string> = {}, stdin?: string) {
  return new Promise<{ code: number; out: string; err: string }>((resolve) => {
    const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, ...env } });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("close", (code) => resolve({ code: code ?? -1, out, err }));
    child.stdin.end(stdin ?? "");
  });
}
const freshConfig = () => ({ FERRET_CONFIG: path.join(mkdtempSync(path.join(tmpdir(), "ferret-cli-")), "config.json") });

describe("ferret", () => {
  it("verify: trusted fingerprints in the config decide good (0) or untrusted (3)", async () => {
    const env = freshConfig();
    const unknown = await ferret(["verify", path.join(fixtures, "export.zip")], env);
    assert.equal(unknown.code, 0);
    assert.match(unknown.out, /No trusted fingerprint/);

    assert.equal((await ferret(["trust", "add", "exports", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "--name", "Someone else"], env)).code, 0);
    assert.equal((await ferret(["verify", path.join(fixtures, "export.zip")], env)).code, 3);

    assert.equal((await ferret(["trust", "add", "exports", exportKey, "--name", "Home"], env)).code, 0);
    const good = await ferret(["verify", path.join(fixtures, "export.zip")], env);
    assert.equal(good.code, 0);
    assert.match(good.out, /good — signed by Home/);
    assert.equal(statSync(env.FERRET_CONFIG).mode & 0o777, 0o600);

    // --fingerprint for one check, without the config.
    assert.equal((await ferret(["verify", path.join(fixtures, "export.zip"), "--fingerprint", exportKey], freshConfig())).code, 0);
  });

  it("verify: a backup folder, by its trusted server key; --json", async () => {
    const env = freshConfig();
    const fp = (await ferret(["fingerprint", path.join(fixtures, "backup")], env)).out.trim();
    assert.match(fp, /^SHA256:/);
    await ferret(["trust", "add", "backups", fp, "--name", "NAS"], env);
    const r = await ferret(["verify", path.join(fixtures, "backup"), "--json"], env);
    assert.equal(r.code, 0);
    assert.equal(JSON.parse(r.out).verdict, "good");
    // A backup key doesn't vouch for exports, nor the other way round.
    assert.equal((await ferret(["verify", path.join(fixtures, "export.zip")], env)).code, 0); // no export keys: not compared
    await ferret(["trust", "add", "exports", fp], env);
    assert.equal((await ferret(["verify", path.join(fixtures, "export.zip")], env)).code, 3);
  });

  it("fingerprint of an export, and of a signed PDF, is the household's", async () => {
    assert.equal((await ferret(["fingerprint", path.join(fixtures, "export.zip")])).out.trim(), exportKey);
    assert.equal((await ferret(["fingerprint", path.join(fixtures, "export.pdf")])).out.trim(), exportKey);
  });

  it("verify: a signed PDF by its trusted key", async () => {
    const env = freshConfig();
    await ferret(["trust", "add", "exports", exportKey, "--name", "Home"], env);
    const r = await ferret(["verify", path.join(fixtures, "export.pdf")], env);
    assert.equal(r.code, 0);
    assert.match(r.out, /good — signed by Home/);
  });

  it("export: finds the thing by words and saves its signed ZIP, then verifies it", async () => {
    const zip = readFileSync(path.join(fixtures, "export.zip"));
    let auth = "";
    const server = createServer((req, res) => {
      auth = req.headers.authorization ?? "";
      if (req.url?.startsWith("/api/v1/items?q=")) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ data: [{ id: "0b6f1a52-1111-4222-8333-444455556666", name: "Cordless drill", place: "Garage" }] }));
      } else if (req.url?.startsWith("/api/v1/items/0b6f1a52-1111-4222-8333-444455556666/sheet.pdf")) {
        res.setHeader("content-type", "application/pdf");
        res.setHeader("content-disposition", `attachment; filename="Cordless drill.pdf"`);
        res.end(readFileSync(path.join(fixtures, "export.pdf")));
      } else if (req.url?.startsWith("/api/v1/items/0b6f1a52-1111-4222-8333-444455556666/export.zip")) {
        res.setHeader("content-type", "application/zip");
        res.setHeader("content-disposition", `attachment; filename="Cordless drill.zip"; filename*=UTF-8''Cordless%20drill.zip`);
        res.end(zip);
      } else {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: { message: "Item not found" } }));
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const env = freshConfig();
    await ferret(["config", "set", "url", `http://127.0.0.1:${port}`], env);
    assert.equal((await ferret(["config", "set", "api-key"], env, "ferret_testkey\n")).code, 0);
    await ferret(["trust", "add", "exports", exportKey], env);
    const out = mkdtempSync(path.join(tmpdir(), "ferret-out-"));
    const r = await ferret(["export", "cordless", "drill", "--out", out, "--verify"], env);
    const p = await ferret(["export", "cordless drill", "--pdf", "--out", out, "--verify"], env);
    server.close();
    assert.equal(p.code, 0, p.err);
    assert.match(p.out, /Saved .*Cordless drill\.pdf/);
    assert.equal(r.code, 0, r.err);
    assert.equal(auth, "Bearer ferret_testkey");
    assert.match(r.out, /Saved .*Cordless drill\.zip/);
    assert.match(r.out, /good/);
    assert.ok(statSync(path.join(out, "Cordless drill.zip")).size > 0);
  });

  it("usage mistakes exit 2", async () => {
    assert.equal((await ferret(["verify"])).code, 2);
    assert.equal((await ferret(["trust", "add", "exports", "nope"])).code, 1);
    assert.equal((await ferret(["frobnicate"])).code, 2);
  });
});
