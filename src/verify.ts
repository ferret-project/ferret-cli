/**
 * Checking what Ferret signed, offline: a thing's export (its ZIP, or the folder it unzips to) and backup folders.
 * Each check gives a report — what was looked at, what's wrong — and whether the signing key is one you trust.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { unzipSync } from "fflate";
import { type Trusted } from "./config.ts";
import { normalizeFingerprint, parsePublicKey, fingerprint as fingerprintOf, sha256, verify } from "./sshsig.ts";

export const EXPORT_NAMESPACE = "ferret-export";
export const BACKUP_NAMESPACE = "ferret-backup";
/** Files that come with an export's signature rather than under it. */
const SIGNATURE_FILES = new Set(["SHA256SUMS", "SHA256SUMS.sig", "allowed_signers", "ferret-signing-key.pub", "VERIFY.txt"]);

export type Verdict = "good" | "untrusted" | "unsigned" | "bad";
export interface Report {
  what: string;
  verdict: Verdict;
  /** The signing key's fingerprint, when the signature holds. */
  fingerprint: string | null;
  /** The trusted key's name, when it's one you trust. */
  trustedAs: string | null;
  checked: string[];
  problems: string[];
  warnings: string[];
}

/** Good / untrusted from the signer's key and the fingerprints you trust (none given: not compared, with a warning). */
function trustOf(fp: string, trusted: Trusted[], warnings: string[]) {
  if (!trusted.length) {
    warnings.push("No trusted fingerprint to compare with — the files match the key that came with them, but that key could be anyone's. Add yours with `ferret trust add`.");
    return { verdict: "good" as const, trustedAs: null };
  }
  const hit = trusted.find((t) => normalizeFingerprint(t.fingerprint) === fp);
  return hit ? { verdict: "good" as const, trustedAs: hit.name ?? fp } : { verdict: "untrusted" as const, trustedAs: null };
}

/** An export's files by path inside its folder: from a ZIP, or an unzipped folder. */
export function readExport(target: string): Map<string, Uint8Array> {
  const files = new Map<string, Uint8Array>();
  if (statSync(target).isDirectory()) {
    const walk = (dir: string, prefix: string) => {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name);
        const rel = prefix ? `${prefix}/${name}` : name;
        if (statSync(full).isDirectory()) walk(full, rel);
        else files.set(rel, new Uint8Array(readFileSync(full)));
      }
    };
    walk(target, "");
  } else {
    const entries = unzipSync(new Uint8Array(readFileSync(target)));
    for (const [name, data] of Object.entries(entries)) if (!name.endsWith("/")) files.set(name, data);
  }
  // Inside its one folder (<name>/item.json): paths from there.
  const json = [...files.keys()].find((n) => n === "item.json" || /^[^/]+\/item\.json$/.test(n));
  if (!json) throw new Error("This isn't a thing exported from Ferret (no item.json)");
  const root = json.slice(0, -"item.json".length);
  if (!root) return files;
  return new Map([...files].filter(([n]) => n.startsWith(root)).map(([n, d]) => [n.slice(root.length), d]));
}

/** A thing's export: SHA256SUMS signed, every file matching it, nothing added — and whose key signed it. */
export async function verifyExport(target: string, trusted: Trusted[]): Promise<Report> {
  const files = readExport(target);
  const report: Report = { what: target, verdict: "bad", fingerprint: null, trustedAs: null, checked: [], problems: [], warnings: [] };
  try {
    const item = JSON.parse(new TextDecoder().decode(files.get("item.json")!)) as { item?: { name?: string }; exportedAt?: string };
    report.what = `${item.item?.name ?? "?"} (exported ${item.exportedAt ?? "at an unknown time"})`;
  } catch {
    report.problems.push("item.json can't be read");
  }
  const sums = files.get("SHA256SUMS");
  const sig = files.get("SHA256SUMS.sig");
  if (!sums || !sig) {
    report.verdict = "unsigned";
    report.problems.push("It isn't signed (no SHA256SUMS or SHA256SUMS.sig)");
    return report;
  }
  try {
    const signed = await verify(new TextDecoder().decode(sig), sums, EXPORT_NAMESPACE);
    report.fingerprint = signed.fingerprint;
    report.checked.push(`signature by ${signed.fingerprint}`);
  } catch (e) {
    report.problems.push(`The signature doesn't hold: ${(e as Error).message}`);
  }
  const listed = new Map<string, string>();
  for (const line of new TextDecoder().decode(sums).split("\n")) {
    const m = line.match(/^([0-9a-f]{64}) {2}(.+)$/);
    if (m) listed.set(m[2]!, m[1]!);
  }
  for (const [p, hash] of listed) {
    const data = files.get(p);
    if (!data) report.problems.push(`${p} is missing`);
    else if ((await sha256(data)) !== hash) report.problems.push(`${p} has changed`);
    else report.checked.push(p);
  }
  for (const p of files.keys()) if (!listed.has(p) && !SIGNATURE_FILES.has(p)) report.problems.push(`${p} was added`);
  // The key that came with it should be the one that signed it (a mismatch means someone swapped the .pub).
  const pub = files.get("ferret-signing-key.pub");
  if (pub && report.fingerprint) {
    const shipped = await fingerprintOf(parsePublicKey(new TextDecoder().decode(pub)));
    if (shipped !== report.fingerprint) report.warnings.push(`ferret-signing-key.pub (${shipped}) isn't the key that signed it`);
  }
  if (report.problems.length) return report;
  Object.assign(report, trustOf(report.fingerprint!, trusted, report.warnings));
  return report;
}

/** Backup snapshots in a folder, newest first. */
export function snapshotsIn(dir: string) {
  const snaps = path.join(dir, "snapshots");
  if (!existsSync(snaps)) throw new Error(`${dir} isn't a Ferret backup folder (no snapshots/)`);
  return readdirSync(snaps)
    .filter((n) => n.endsWith(".json"))
    .map((n) => n.slice(0, -".json".length))
    .sort()
    .reverse();
}

interface Manifest {
  createdAt: string;
  dbEncSha256?: string;
  files: { key: string; size: number; sha256?: string }[];
  counts?: { items: number; attachments: number };
}

/** One backup: its manifest signed, the database copy and every file it needs there and matching. */
export async function verifyBackup(dir: string, snapshot: string, trusted: Trusted[]): Promise<Report> {
  const report: Report = { what: snapshot, verdict: "bad", fingerprint: null, trustedAs: null, checked: [], problems: [], warnings: [] };
  const at = (rel: string) => path.join(dir, rel);
  const manifestBytes = new Uint8Array(readFileSync(at(`snapshots/${snapshot}.json`)));
  let manifest: Manifest;
  try {
    manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as Manifest;
  } catch {
    report.problems.push("Its manifest can't be read");
    return report;
  }
  report.what = `${snapshot} (${manifest.counts ? `${manifest.counts.items} things, ` : ""}${manifest.files.length} files)`;
  const sigFile = at(`snapshots/${snapshot}.json.sig`);
  if (!existsSync(sigFile)) {
    report.verdict = "unsigned";
    report.problems.push("It isn't signed (made before Ferret signed backups, or the .sig is gone)");
  } else {
    try {
      const signed = await verify(readFileSync(sigFile, "utf8"), manifestBytes, BACKUP_NAMESPACE);
      report.fingerprint = signed.fingerprint;
      report.checked.push(`signature by ${signed.fingerprint}`);
    } catch (e) {
      report.problems.push(`The signature doesn't hold: ${(e as Error).message}`);
    }
  }
  const db = at(`snapshots/${snapshot}.db.enc`);
  if (!existsSync(db)) report.problems.push(`${snapshot}.db.enc is missing`);
  else if (!manifest.dbEncSha256) report.warnings.push("The manifest has no hash for the database copy (an older backup)");
  else if ((await sha256(new Uint8Array(readFileSync(db)))) !== manifest.dbEncSha256) report.problems.push(`${snapshot}.db.enc has changed`);
  else report.checked.push(`${snapshot}.db.enc`);
  let unhashed = 0;
  for (const f of manifest.files) {
    const file = at(`files/${f.key}`);
    if (!existsSync(file)) {
      report.problems.push(`files/${f.key} is missing`);
      continue;
    }
    if (!f.sha256) {
      unhashed++;
      if (statSync(file).size !== f.size) report.problems.push(`files/${f.key} isn't the size the manifest says`);
      continue;
    }
    if ((await sha256(new Uint8Array(readFileSync(file)))) !== f.sha256) report.problems.push(`files/${f.key} has changed`);
  }
  report.checked.push(`${manifest.files.length - unhashed} files by hash`);
  if (unhashed) report.warnings.push(`${unhashed} files have no hash in the manifest (an older backup): checked by size only`);
  if (report.problems.length) return report;
  Object.assign(report, trustOf(report.fingerprint!, trusted, report.warnings));
  return report;
}

// ── A thing's signed PDF (drawn by the server; Ferret's lib/item-pdf.ts) ───────────────────────────────────────────

const PDF_SIGNATURE_START = "\n%FERRET-SIGNATURE\n";
const PDF_SIGNATURE_END = "%END-FERRET-SIGNATURE\n";

/** The PDF and its signature: the block after %%EOF, each line a PDF comment. Null when there's none. */
export function splitSignedPdf(bytes: Uint8Array): { pdf: Uint8Array; signature: string } | null {
  const tail = new TextDecoder("latin1").decode(bytes.subarray(Math.max(0, bytes.length - 2048)));
  const at = tail.lastIndexOf(PDF_SIGNATURE_START);
  if (at < 0 || !tail.endsWith(PDF_SIGNATURE_END)) return null;
  const cut = bytes.length - (tail.length - at);
  const block = tail.slice(at + PDF_SIGNATURE_START.length, tail.length - PDF_SIGNATURE_END.length);
  return { pdf: bytes.subarray(0, cut), signature: `${block.split("\n").filter(Boolean).map((l) => l.replace(/^%/, "")).join("\n")}\n` };
}

export const isPdf = (target: string) => {
  if (statSync(target).isDirectory()) return false;
  const head = readFileSync(target).subarray(0, 5).toString("latin1");
  return head === "%PDF-";
};

/** A thing's signed PDF: the signature over every byte before it, by a key you trust. */
export async function verifyPdf(target: string, trusted: Trusted[]): Promise<Report> {
  const bytes = new Uint8Array(readFileSync(target));
  const report: Report = { what: path.basename(target), verdict: "bad", fingerprint: null, trustedAs: null, checked: [], problems: [], warnings: [] };
  const split = splitSignedPdf(bytes);
  if (!split) {
    report.verdict = "unsigned";
    report.problems.push("It isn't signed by Ferret (a printout, or saved from another app)");
    return report;
  }
  try {
    const signed = await verify(split.signature, split.pdf, EXPORT_NAMESPACE);
    report.fingerprint = signed.fingerprint;
    report.checked.push(`signature by ${signed.fingerprint}`, `${split.pdf.length} bytes of PDF`);
  } catch (e) {
    report.problems.push(`It changed after it was signed, or the signature is damaged: ${(e as Error).message}`);
    return report;
  }
  Object.assign(report, trustOf(report.fingerprint!, trusted, report.warnings));
  return report;
}
