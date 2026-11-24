#!/usr/bin/env node
/**
 * ferret — check what a Ferret signed, and export from one.
 *
 *   ferret verify <export.zip | file.pdf | export folder | backup folder>   check an export, a signed PDF or a backup
 *   ferret fingerprint <file>                                     a key's (or an export's / backup's) fingerprint
 *   ferret trust add exports|backups <fingerprint> [--name N]     keys you accept
 *   ferret trust list | remove <fingerprint> | pull               (pull: your household's export key, from the server)
 *   ferret config set url <url> | set api-key | show              where your Ferret is, and its API key (from stdin)
 *   ferret export <id or words> [--pdf] [--out DIR] [--parts a,b] a thing's signed ZIP (or PDF), by id or search
 *
 * Exit codes: 0 good · 1 something's wrong (changed, missing, bad signature) · 2 usage · 3 signed by a key you don't
 * trust · 4 not signed.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { unzipSync } from "fflate";
import { type Config, type TrustKind, configPath, loadConfig, saveConfig, server } from "./config.ts";
import { PARTS, downloadExport, householdKey, search } from "./api.ts";
import { fingerprint, normalizeFingerprint, parsePublicKey } from "./sshsig.ts";
import { type Report, isPdf, snapshotsIn, splitSignedPdf, verifyBackup, verifyExport, verifyPdf } from "./verify.ts";
import { verify as verifySig } from "./sshsig.ts";

const VERSION = "0.2.0";
const HELP = `ferret ${VERSION} — check what a Ferret signed, and export from one

Usage:
  ferret verify <path> [--fingerprint FP]... [--all] [--snapshot NAME] [--json]
      <path> is a thing's export (.zip, or the folder it unzips to), its signed PDF, or a backup folder.
      Backups: the newest snapshot, --snapshot NAME, or --all.
      --fingerprint: a key to accept for this check, besides the trusted ones in your config.
  ferret fingerprint <file.pub | allowed_signers | export.zip | signed .pdf | backup folder>
  ferret trust add exports|backups <fingerprint> [--name NAME]
  ferret trust remove <fingerprint>
  ferret trust list
  ferret trust pull                 your household's export key, from your Ferret (needs url and api-key)
  ferret config set url <https://your-ferret>
  ferret config set api-key         reads the key from stdin (so it stays out of your shell history)
  ferret config show
  ferret export <item id | words> [--pdf] [--out DIR] [--parts photos,documents,…] [--verify]
      the signed ZIP, or with --pdf the signed PDF

Settings: ${configPath()} (FERRET_URL, FERRET_API_KEY and FERRET_CONFIG override it).
Exit codes: 0 good, 1 changed or broken, 2 usage, 3 signed by a key you don't trust, 4 not signed.`;

class Usage extends Error {}

function print(r: Report, json: boolean) {
  if (json) {
    process.stdout.write(`${JSON.stringify(r)}\n`);
    return;
  }
  const mark = { good: "✔", untrusted: "!", unsigned: "?", bad: "✘" }[r.verdict];
  const words = {
    good: r.trustedAs ? `good — signed by ${r.trustedAs}` : "good",
    untrusted: `signed by a key you don't trust (${r.fingerprint})`,
    unsigned: "not signed",
    bad: "changed or broken",
  }[r.verdict];
  process.stdout.write(`${mark} ${r.what}: ${words}\n`);
  if (r.fingerprint && r.verdict === "good") process.stdout.write(`  key ${r.fingerprint}\n`);
  for (const p of r.problems) process.stdout.write(`  ✘ ${p}\n`);
  for (const w of r.warnings) process.stdout.write(`  ! ${w}\n`);
}
const exitFor = (reports: Report[]) =>
  reports.some((r) => r.verdict === "bad") ? 1 : reports.some((r) => r.verdict === "untrusted") ? 3 : reports.some((r) => r.verdict === "unsigned") ? 4 : 0;

const isBackupFolder = (p: string) => statSync(p).isDirectory() && existsSync(path.join(p, "snapshots"));

async function verifyCommand(args: string[], config: Config) {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { fingerprint: { type: "string", multiple: true }, all: { type: "boolean" }, snapshot: { type: "string" }, json: { type: "boolean" } } });
  const target = positionals[0];
  if (!target) throw new Usage("verify: which file or folder?");
  if (!existsSync(target)) throw new Error(`${target} doesn't exist`);
  const extra = (values.fingerprint ?? []).map((fp) => ({ fingerprint: normalizeFingerprint(fp), name: "the fingerprint you gave" }));
  const reports: Report[] = [];
  if (isBackupFolder(target)) {
    const trusted = [...(config.trust?.backups ?? []), ...extra];
    const all = snapshotsIn(target);
    if (!all.length) throw new Error("No finished backups in that folder");
    const which = values.snapshot ? [values.snapshot] : values.all ? all : [all[0]!];
    for (const s of which) {
      if (!all.includes(s)) throw new Error(`No snapshot ${s} (there are: ${all.slice(0, 5).join(", ")}…)`);
      reports.push(await verifyBackup(target, s, trusted));
    }
  } else if (isPdf(target)) {
    reports.push(await verifyPdf(target, [...(config.trust?.exports ?? []), ...extra]));
  } else {
    reports.push(await verifyExport(target, [...(config.trust?.exports ?? []), ...extra]));
  }
  for (const r of reports) print(r, Boolean(values.json));
  return exitFor(reports);
}

async function fingerprintCommand(args: string[]) {
  const target = args[0];
  if (!target) throw new Usage("fingerprint: of which file?");
  let keyText: string;
  if (statSync(target).isDirectory()) {
    const pub = [path.join(target, "signing-key.pub"), path.join(target, "ferret-signing-key.pub")].find(existsSync);
    if (!pub) throw new Error("No signing-key.pub in that folder");
    keyText = readFileSync(pub, "utf8");
  } else if (isPdf(target)) {
    // A signed PDF: the key inside its signature (checked first, so a damaged one isn't fingerprinted).
    const split = splitSignedPdf(new Uint8Array(readFileSync(target)));
    if (!split) throw new Error("That PDF isn't signed by Ferret");
    process.stdout.write(`${(await verifySig(split.signature, split.pdf, "ferret-export")).fingerprint}\n`);
    return 0;
  } else if (target.endsWith(".zip")) {
    const entries = unzipSync(new Uint8Array(readFileSync(target)));
    const pub = Object.keys(entries).find((n) => n.endsWith("ferret-signing-key.pub"));
    if (!pub) throw new Error("No ferret-signing-key.pub in that ZIP");
    keyText = new TextDecoder().decode(entries[pub]);
  } else {
    keyText = readFileSync(target, "utf8");
  }
  process.stdout.write(`${await fingerprint(parsePublicKey(keyText))}\n`);
  return 0;
}

async function trustCommand(args: string[], config: Config) {
  const [sub, ...rest] = args;
  const trust = (config.trust ??= {});
  if (sub === "list") {
    for (const kind of ["exports", "backups"] as const) {
      process.stdout.write(`${kind}:\n`);
      for (const t of trust[kind] ?? []) process.stdout.write(`  ${t.fingerprint}${t.name ? `  ${t.name}` : ""}\n`);
      if (!(trust[kind] ?? []).length) process.stdout.write("  (none)\n");
    }
    return 0;
  }
  if (sub === "add") {
    const { values, positionals } = parseArgs({ args: rest, allowPositionals: true, options: { name: { type: "string" } } });
    const [kind, fp] = positionals;
    if ((kind !== "exports" && kind !== "backups") || !fp) throw new Usage("trust add exports|backups <fingerprint> [--name NAME]");
    const fingerprint = normalizeFingerprint(fp);
    if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)) throw new Error(`${fp} doesn't look like a key fingerprint (SHA256:… with 43 characters)`);
    const list = (trust[kind as TrustKind] ??= []).filter((t) => t.fingerprint !== fingerprint);
    list.push({ fingerprint, ...(values.name ? { name: values.name } : {}) });
    trust[kind as TrustKind] = list;
    process.stdout.write(`Trusting ${fingerprint} for ${kind} — ${saveConfig(config)}\n`);
    return 0;
  }
  if (sub === "remove") {
    const fp = rest[0] && normalizeFingerprint(rest[0]);
    if (!fp) throw new Usage("trust remove <fingerprint>");
    for (const kind of ["exports", "backups"] as const) trust[kind] = (trust[kind] ?? []).filter((t) => t.fingerprint !== fp);
    process.stdout.write(`Removed ${fp} — ${saveConfig(config)}\n`);
    return 0;
  }
  if (sub === "pull") {
    const key = await householdKey(server(config));
    // The fingerprint the server says should be the one its key gives.
    const fp = await fingerprint(parsePublicKey(key.publicKey));
    if (fp !== key.fingerprint) throw new Error("The server's key and fingerprint don't agree — not trusting it");
    const host = new URL(server(config).url).host;
    const list = (trust.exports ??= []).filter((t) => t.fingerprint !== fp);
    list.push({ fingerprint: fp, name: host });
    trust.exports = list;
    process.stdout.write(`Trusting ${fp} (${host}) for exports — compare it with Settings → Household → Signing key once. ${saveConfig(config)}\n`);
    return 0;
  }
  throw new Usage("trust add|remove|list|pull");
}

async function readStdin() {
  if (process.stdin.isTTY) process.stderr.write("Paste the API key, then press Enter (Ctrl-D to finish):\n");
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) {
    chunks.push(c as Buffer);
    if (process.stdin.isTTY && Buffer.concat(chunks).includes(10)) break;
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}

async function configCommand(args: string[], config: Config) {
  const [sub, what, value] = args;
  if (sub === "show") {
    const shown = { ...config, ...(config.apiKey ? { apiKey: `${config.apiKey.slice(0, 10)}…` } : {}) };
    process.stdout.write(`${configPath()}\n${JSON.stringify(shown, null, 2)}\n`);
    return 0;
  }
  if (sub === "set" && what === "url") {
    if (!value || !/^https?:\/\//.test(value)) throw new Usage("config set url https://your-ferret");
    config.url = value.replace(/\/+$/, "");
    process.stdout.write(`Saved — ${saveConfig(config)}\n`);
    return 0;
  }
  if (sub === "set" && what === "api-key") {
    const key = value ?? (await readStdin());
    if (value) process.stderr.write("warning: a key on the command line stays in your shell history — next time, leave it off and paste it\n");
    if (!/^ferret_/.test(key)) throw new Error("That doesn't look like a Ferret API key (ferret_…)");
    config.apiKey = key;
    process.stdout.write(`Saved — ${saveConfig(config)}\n`);
    return 0;
  }
  throw new Usage("config set url <url> | set api-key | show");
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function exportCommand(args: string[], config: Config) {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { out: { type: "string" }, parts: { type: "string" }, verify: { type: "boolean" }, pdf: { type: "boolean" } } });
  const what = positionals.join(" ").trim();
  if (!what) throw new Usage("export <item id | words>");
  const parts = values.parts?.split(",").map((p) => p.trim()).filter(Boolean);
  const unknown = parts?.filter((p) => !(PARTS as readonly string[]).includes(p));
  if (unknown?.length) throw new Usage(`Unknown parts: ${unknown.join(", ")} (there are: ${PARTS.join(", ")})`);
  const s = server(config);
  let id = what;
  if (!UUID.test(what)) {
    const found = await search(s, what);
    if (!found.length) throw new Error(`Nothing matches "${what}"`);
    const exact = found.filter((f) => f.name.toLowerCase() === what.toLowerCase());
    if (found.length > 1 && exact.length !== 1) {
      process.stdout.write(`More than one thing matches — export one by its id:\n`);
      for (const f of found) process.stdout.write(`  ${f.id}  ${f.name}${f.place ? `  (${f.place})` : ""}\n`);
      return 2;
    }
    id = (exact[0] ?? found[0]!).id;
  }
  const to = await downloadExport(s, id, { dir: values.out, parts, pdf: values.pdf });
  process.stdout.write(`Saved ${to}\n`);
  if (!values.verify) return 0;
  const r = values.pdf ? await verifyPdf(to, config.trust?.exports ?? []) : await verifyExport(to, config.trust?.exports ?? []);
  print(r, false);
  return exitFor([r]);
}

async function main(argv: string[]) {
  const [command, ...rest] = argv;
  if (!command || command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(`${HELP}\n`);
    return command ? 0 : 2;
  }
  if (command === "--version" || command === "-v") {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  const config = loadConfig();
  switch (command) {
    case "verify":
      return verifyCommand(rest, config);
    case "fingerprint":
      return fingerprintCommand(rest);
    case "trust":
      return trustCommand(rest, config);
    case "config":
      return configCommand(rest, config);
    case "export":
      return exportCommand(rest, config);
    default:
      throw new Usage(`Unknown command: ${command}`);
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`ferret: ${err instanceof Error ? err.message : String(err)}\n`);
    if (err instanceof Usage) process.stderr.write("Run `ferret help` for the commands.\n");
    process.exit(err instanceof Usage ? 2 : 1);
  },
);
