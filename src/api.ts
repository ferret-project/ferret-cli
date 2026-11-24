/** Talking to a Ferret with an API key: finding things, downloading a thing's signed export, the household's key. */
import { createWriteStream } from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import path from "node:path";

export interface Server {
  url: string;
  apiKey: string;
}
export const PARTS = ["photos", "documents", "notes", "links", "warranties", "maintenance", "repairs", "loans", "stock", "history"] as const;

async function call(s: Server, pathAndQuery: string) {
  const res = await fetch(`${s.url}/api/v1${pathAndQuery}`, { headers: { Authorization: `Bearer ${s.apiKey}`, "User-Agent": "ferret-cli" } });
  if (!res.ok) {
    let message = res.statusText;
    try {
      message = ((await res.json()) as { error?: { message?: string } }).error?.message ?? message;
    } catch {
      // not JSON
    }
    throw new Error(`${res.status} ${message}`);
  }
  return res;
}

export interface Found {
  id: string;
  name: string;
  place: string | null;
}
/** Things matching some words (Ferret's own search), best first. */
export async function search(s: Server, words: string, limit = 20): Promise<Found[]> {
  const res = await call(s, `/items?q=${encodeURIComponent(words)}&limit=${limit}&judge=later`);
  const page = (await res.json()) as { data: Found[] };
  return page.data.map((i) => ({ id: i.id, name: i.name, place: i.place }));
}

/** Downloads a thing's signed export (its ZIP, or with `pdf` its signed PDF) into `dir` (or to `file`); returns where. */
export async function downloadExport(s: Server, itemId: string, opts: { dir?: string; file?: string; parts?: string[]; pdf?: boolean }) {
  const q = opts.parts ? `?parts=${opts.parts.join(",")}` : "";
  const res = await call(s, `/items/${encodeURIComponent(itemId)}/${opts.pdf ? "sheet.pdf" : "export.zip"}${q}`);
  const disposition = res.headers.get("content-disposition") ?? "";
  const name = decodeURIComponent(disposition.match(/filename\*=UTF-8''([^;]+)/)?.[1] ?? "") || disposition.match(/filename="([^"]+)"/)?.[1] || `${itemId}.${opts.pdf ? "pdf" : "zip"}`;
  const to = opts.file ?? path.join(opts.dir ?? ".", path.basename(name));
  await pipeline(Readable.fromWeb(res.body! as import("node:stream/web").ReadableStream), createWriteStream(to));
  return to;
}

export interface SigningKey {
  publicKey: string;
  fingerprint: string;
  allowedSigners: string;
  namespace: string;
}
/** The household's export key (Settings → Household → Signing key). */
export async function householdKey(s: Server): Promise<SigningKey> {
  return (await (await call(s, "/household/signing-key")).json()) as SigningKey;
}
