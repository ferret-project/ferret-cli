# ferret-cli

Check what a [Ferret](https://github.com/ferret-project/ferret) signed — a thing's export or a backup — and export
things from your Ferret.

Ferret signs two kinds of files with Ed25519 keys, as OpenSSH signatures:

- **A thing's export** (Print or export → Download signed ZIP): its Markdown, `item.json`, photos and documents, with
  `SHA256SUMS` signed by your **household's** key.
- **Backups**: each snapshot's manifest (the database copy's and every file's SHA-256) signed by the **server's** key.

`ferret verify` checks the signature, every file against it, and that the key is one **you** said to trust — so the
check doesn't rest on the key that came with the files.

## Install

Needs Node.js 22.6 or newer.

```bash
git clone https://github.com/ferret-project/ferret-cli.git
cd ferret-cli
npm ci && npm run build
npm link            # puts `ferret` on your PATH
```

## Trust your keys once

Get the fingerprints from Ferret, by a way you trust (your own screen):

- exports: **Settings → Household → Signing key**
- backups: **Settings → Server → Keys → Backup signing key**

```bash
ferret trust add exports SHA256:… --name Home
ferret trust add backups SHA256:… --name NAS
ferret trust list
```

Or, with your Ferret's address and an API key set (below), `ferret trust pull` adds your household's export key —
compare it with Settings once.

## Verify

```bash
ferret verify "Cordless drill.zip"          # an export (or the folder it unzips to)
ferret verify /mnt/nas/ferret-backups       # the newest backup in a backup folder
ferret verify /mnt/nas/ferret-backups --all # every backup there
ferret verify export.zip --fingerprint SHA256:…   # accept this key for one check
ferret verify export.zip --json             # for scripts
```

```
✔ Cordless drill (exported 2026-11-24T17:56:41.267Z): good — signed by Home
  key SHA256:HRln2JMmTBqAphk/xV1IsRxeHxMV4aUyIn+L5JF1kjw
```

| Exit code | Meaning |
| --- | --- |
| 0 | good: signed, nothing changed, by a key you trust (or no trusted key set yet — it says so) |
| 1 | something changed, is missing or was added, or the signature doesn't hold |
| 2 | usage |
| 3 | signed by a key you don't trust |
| 4 | not signed |

Checking a backup needs no `FILES_KEY`: it checks the encrypted files as they are, not what's inside them.

`ferret fingerprint <file.pub | export.zip | backup folder>` prints the fingerprint of the key a file carries.

## Export from your Ferret

Make an API key in Ferret (**Settings → Claude & API → New key**; read-only is enough), then:

```bash
ferret config set url https://ferret.example.com
ferret config set api-key        # paste it; it isn't left in your shell history
ferret export "cordless drill" --out ~/exports --verify
ferret export 7e7fa822-ce72-400b-8ad7-264d8670fcd0 --parts photos,documents,warranties
```

If more than one thing matches, it lists them with their ids. `--parts` takes any of photos, documents, notes, links,
warranties, maintenance, repairs, loans, stock, history (the details are always there).

## Settings

`~/.config/ferret/config.json` (or `$XDG_CONFIG_HOME/ferret/config.json`), readable by you only:

```json
{
  "url": "https://ferret.example.com",
  "apiKey": "ferret_…",
  "trust": {
    "exports": [{ "fingerprint": "SHA256:…", "name": "Home" }],
    "backups": [{ "fingerprint": "SHA256:…", "name": "NAS" }]
  }
}
```

`FERRET_URL`, `FERRET_API_KEY` and `FERRET_CONFIG` override it. A Ferret with a certificate from your own authority:
`NODE_EXTRA_CA_CERTS=/path/to/ca.pem ferret export …`.

## Without this tool

Everything here can be checked with `ssh-keygen` and `shasum` too — each export's `VERIFY.txt` says how, and so does
Ferret's help (Backups → Signed backups).

## License

MIT
