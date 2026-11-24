/**
 * OpenSSH signatures (SSHSIG, PROTOCOL.sshsig) with Ed25519 keys — what Ferret signs exports and backups with — and
 * key fingerprints as `ssh-keygen -l` prints them. Node's own WebCrypto; nothing else.
 */
const utf8 = new TextEncoder();
/** WebCrypto wants bytes over a plain ArrayBuffer. */
const bs = (u: Uint8Array) => u as Uint8Array<ArrayBuffer>;
const text = (b: Uint8Array) => new TextDecoder().decode(b);
export const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const fromB64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));

function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
function sshString(data: Uint8Array | string) {
  const bytes = typeof data === "string" ? utf8.encode(data) : data;
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, bytes.length);
  return concat(len, bytes);
}
/** A reader over SSH's wire format: uint32s and length-prefixed strings. */
function reader(blob: Uint8Array) {
  let at = 0;
  const take = (n: number) => {
    if (at + n > blob.length) throw new Error("truncated");
    return blob.subarray(at, (at += n));
  };
  const u32 = () => {
    const bytes = take(4);
    return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0);
  };
  const str = () => take(u32());
  return { take, u32, str, done: () => at === blob.length };
}

/** "SHA256:…" for an Ed25519 public key (its raw 32 bytes), as ssh-keygen -l shows it. */
export async function fingerprint(publicRaw: Uint8Array) {
  const blob = concat(sshString("ssh-ed25519"), sshString(publicRaw));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bs(blob)));
  return `SHA256:${b64(digest).replace(/=+$/, "")}`;
}

/** The raw key from an OpenSSH public key line ("ssh-ed25519 AAAA… comment"), or from an allowed_signers line. */
export function parsePublicKey(line: string) {
  const m = line.match(/ssh-ed25519\s+([A-Za-z0-9+/=]+)/);
  if (!m) throw new Error("Not an ssh-ed25519 public key");
  const r = reader(fromB64(m[1]!));
  if (text(r.str()) !== "ssh-ed25519") throw new Error("Not an ssh-ed25519 public key");
  const raw = r.str();
  if (raw.length !== 32) throw new Error("Not an ssh-ed25519 public key");
  return raw;
}

/** A fingerprint written by a person: "SHA256:abc…", or just "abc…". */
export const normalizeFingerprint = (fp: string) => {
  const s = fp.trim();
  return s.startsWith("SHA256:") ? s : `SHA256:${s}`;
};

export interface Verified {
  /** The signing key's fingerprint. */
  fingerprint: string;
  publicKey: string;
}

/**
 * Checks an armoured SSH signature of `message` for `namespace` against the Ed25519 key inside it. Returns that key's
 * fingerprint, or throws saying why it doesn't hold.
 */
export async function verify(armoured: string, message: Uint8Array, namespace: string): Promise<Verified> {
  const body = armoured.match(/-----BEGIN SSH SIGNATURE-----([\s\S]*?)-----END SSH SIGNATURE-----/)?.[1];
  if (!body) throw new Error("not an SSH signature");
  const r = reader(fromB64(body.replace(/\s+/g, "")));
  if (text(r.take(6)) !== "SSHSIG") throw new Error("not an SSH signature");
  if (r.u32() !== 1) throw new Error("unknown signature version");
  const pub = reader(r.str());
  if (text(pub.str()) !== "ssh-ed25519") throw new Error("signed with a key type other than Ed25519");
  const publicRaw = pub.str();
  const ns = text(r.str());
  if (ns !== namespace) throw new Error(`signed for "${ns}", not "${namespace}"`);
  r.str(); // reserved
  const hashAlg = text(r.str());
  if (hashAlg !== "sha512" && hashAlg !== "sha256") throw new Error(`unknown hash ${hashAlg}`);
  const sigBlob = reader(r.str());
  if (text(sigBlob.str()) !== "ssh-ed25519") throw new Error("not an Ed25519 signature");
  const sig = sigBlob.str();
  const hash = new Uint8Array(await crypto.subtle.digest(hashAlg === "sha512" ? "SHA-512" : "SHA-256", bs(message)));
  const signed = concat(utf8.encode("SSHSIG"), sshString(namespace), sshString(""), sshString(hashAlg), sshString(hash));
  const key = await crypto.subtle.importKey("raw", bs(publicRaw), { name: "Ed25519" }, false, ["verify"]);
  if (!(await crypto.subtle.verify({ name: "Ed25519" }, key, bs(sig), bs(signed)))) throw new Error("the signature doesn't match");
  return { fingerprint: await fingerprint(publicRaw), publicKey: `ssh-ed25519 ${b64(concat(sshString("ssh-ed25519"), sshString(publicRaw)))}` };
}

/** Signs like Ferret does — for the tests' own fixtures. */
export async function sign(privateKey: CryptoKey, publicRaw: Uint8Array, message: Uint8Array, namespace: string) {
  const magic = utf8.encode("SSHSIG");
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-512", bs(message)));
  const signed = concat(magic, sshString(namespace), sshString(""), sshString("sha512"), sshString(hash));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, bs(signed)));
  const pubBlob = concat(sshString("ssh-ed25519"), sshString(publicRaw));
  const blob = concat(magic, new Uint8Array([0, 0, 0, 1]), sshString(pubBlob), sshString(namespace), sshString(""), sshString("sha512"), sshString(concat(sshString("ssh-ed25519"), sshString(sig))));
  return `-----BEGIN SSH SIGNATURE-----\n${b64(blob).match(/.{1,70}/g)!.join("\n")}\n-----END SSH SIGNATURE-----\n`;
}

export const sha256 = async (data: Uint8Array) => Buffer.from(await crypto.subtle.digest("SHA-256", bs(data))).toString("hex");
