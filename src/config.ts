/**
 * The CLI's settings: ~/.config/ferret/config.json (or $XDG_CONFIG_HOME/ferret/config.json), readable by you only.
 *
 *   {
 *     "url": "https://ferret.example.com",        your Ferret, for `ferret export`
 *     "apiKey": "ferret_…",                       an API key from Settings → Claude & API (read-only is enough)
 *     "trust": {
 *       "exports": [{ "fingerprint": "SHA256:…", "name": "Home" }],   household keys whose exports you accept
 *       "backups": [{ "fingerprint": "SHA256:…", "name": "NAS" }]     server keys whose backups you accept
 *     }
 *   }
 *
 * FERRET_URL and FERRET_API_KEY override the file; FERRET_CONFIG points at another file.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

export type TrustKind = "exports" | "backups";
export interface Trusted {
  fingerprint: string;
  name?: string;
}
export interface Config {
  url?: string;
  apiKey?: string;
  trust?: Partial<Record<TrustKind, Trusted[]>>;
}

export function configPath() {
  if (process.env.FERRET_CONFIG) return process.env.FERRET_CONFIG;
  const base = process.env.XDG_CONFIG_HOME || path.join(homedir(), ".config");
  return path.join(base, "ferret", "config.json");
}

export function loadConfig(): Config {
  const file = configPath();
  if (!existsSync(file)) return {};
  // It may hold an API key: say so if others can read it.
  if (process.platform !== "win32" && (statSync(file).mode & 0o077) !== 0) {
    process.stderr.write(`warning: ${file} can be read by other users — chmod 600 it\n`);
  }
  let config: Config;
  try {
    config = JSON.parse(readFileSync(file, "utf8")) as Config;
  } catch {
    throw new Error(`${file} isn't valid JSON`);
  }
  return config;
}

export function saveConfig(config: Config) {
  const file = configPath();
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  return file;
}

/** The server and key to use: the environment first, then the file. */
export function server(config: Config) {
  const url = (process.env.FERRET_URL || config.url || "").replace(/\/+$/, "");
  const apiKey = process.env.FERRET_API_KEY || config.apiKey || "";
  if (!url) throw new Error("No Ferret address: run `ferret config set url https://your-ferret`, or set FERRET_URL");
  if (!apiKey) throw new Error("No API key: run `ferret config set api-key` (it reads the key from stdin), or set FERRET_API_KEY");
  return { url, apiKey };
}
