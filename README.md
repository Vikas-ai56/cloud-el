# SecureVault localhost demo

Python FastAPI backend, SQLite accounts/metadata, browser AES-256-GCM encryption, and server decryption. No Clerk, cloud account, Docker, or runtime package downloads are required on this prepared workspace.

## Start

```sh
cd /Users/kvikas/cloud_el
./run.sh
```

Open **http://localhost:3000**. `PORT=8000 ./run.sh` selects another port.

| Account | Login password | Encryption passphrase |
|---|---|---|
| alice@securevault.local | DemoLogin123! | vault-demo-phrase |
| bob@securevault.local | DemoLogin123! | vault-demo-phrase |

Use separate browser profiles or a private window for Alice and Bob. New accounts can register and generate their own encryption keys in the browser.

The prepared `.venv` contains Python dependencies. On a fresh machine use Python 3.12+ and `python3 -m venv .venv`, then `.venv/bin/python -m pip install -r requirements.txt`. Node is used only by one browser-crypto interoperability test, not by the backend or launch script. The browser Argon2id implementation is vendored from MIT-licensed `@noble/hashes` 2.4.0 in `public/vendor`.

## Demo walkthrough

1. Sign in as Alice. Upload `samples/welcome.txt`.
2. Open the file and inspect ciphertext: the API reads actual encrypted bytes from `data/objects`.
3. Decrypt using the encryption passphrase. The API verifies GCM and SHA-256; the browser independently hashes the response before showing it.
4. Upload `samples/welcome-v2.txt` as a new version. Restore version 1 and see version 3 appear without overwriting history.
5. Share with Bob as viewer. Sign in as Bob in another browser profile and decrypt using Bob's passphrase. Viewer actions are enforced in Python. Revoke Bob and try again.
6. Upload `samples/demo-audio.wav` and `samples/demo-video.mp4`, then decrypt and play them. Playback waits for complete verification. File limit: 25 MiB. Preview depends on browser codec support; all formats can be stored/downloaded.
7. Open Audit trail and verify the chain and its external checkpoint.

## Controlled tamper demos

These commands deliberately alter local demo data. Use disposable files or a separate `DATA_DIR`.

```sh
.venv/bin/python scripts/tamper.py object --file-id FILE_ID
.venv/bin/python scripts/tamper.py audit
```

After object tampering, decryption returns HTTP 422 with no plaintext. After audit tampering, verification reports the first broken event. Use `DATA_DIR=/private/tmp/securevault-demo ./run.sh` for a fresh isolated demonstration. Deleting a file in the UI hides it; it retains encrypted history in this prototype.

## Key and storage design

- Login passwords are Argon2id hashed with individual salts. Opaque session IDs are hashed in SQLite; the browser cookie is HttpOnly and SameSite Strict. Cross-origin writes are rejected.
- Every user has a public/private RSA-OAEP SHA-256 key pair. Their private key is AES-GCM encrypted under a passphrase-derived Argon2id key (16 MiB, 2 passes, 1 lane). These parameters are for the local demo and need deployment tuning.
- Every uploaded version has a fresh random 256-bit data key, a random immutable object ID, and separate unique nonces for file and manifest. GCM authenticates the object ID as additional data. The encrypted manifest contains original size, MIME type, and SHA-256.
- Each authorized user receives a separate RSA-wrapped copy of the version data key. Sharing rewraps all historical keys in the owner's browser. New versions must include envelopes for all current recipients.
- For downloads the passphrase goes to the trusted Python API. It unlocks the user's private key, unwraps the file key, authenticates/decrypts everything, and checks SHA-256 before returning bytes. Plaintext, passphrases, and bare data keys are not persisted or logged. Python cannot guarantee immediate erasure of all memory copies.
- SQLite stores metadata; local disk stores ciphertext. File names, sizes, ownership, and permissions are visible metadata. S3/PostgreSQL/Clerk integration is deferred to cloud deployment.
- The audit checkpoint is a separate local file. It detects database tampering, including tail deletion; it does not defend against an attacker controlling both the database and checkpoint filesystem.
- Revocation blocks subsequent API access; it cannot remove previously downloaded files/keys. Encryption passphrase recovery and large-file streaming are outside this version.
- Localhost uses HTTP for development. An internet deployment requires HTTPS, Secure cookies, login rate limiting, secret management, and a managed storage/database adapter.

## Verification

```sh
.venv/bin/python -m pytest -q
```

Tests exercise authentication, browser/Python Argon2id and RSA/AES interoperability, exact file checksums, sharing, viewer denials, revocation, restore, media byte round trips, nonce validation, cross-origin rejection, ciphertext tampering, audit tampering, and deleted-tail checkpoints.

The requested `buglerock-capital/deal-matching` reference returned 404 through the connected GitHub account and was unavailable publicly, so its Clerk implementation could not be inspected. Local SQLite authentication is implemented as authorized.

## Secure upload inbox

Open **Upload inbox → Create upload link** while signed in. Give the request a title, expiry (1 hour, 24 hours, or 7 days), and a submission limit. Copy the full link when it appears; only its hash is stored, so it cannot be retrieved later. Open it in an incognito window to demonstrate an uploader without an account.

The sender chooses a file and optionally provides a name/email label. The browser computes SHA-256, encrypts file and manifest with a fresh AES-GCM key, and wraps that key for the inbox owner's public key. Sender labels are **unverified**. The link authorizes uploads only and never lists or downloads the owner's files. Its secret is in the URL fragment and sent to the API in JSON bodies, keeping it out of normal HTTP access-log URLs.

Submissions are kept outside the file list. The owner can:

- **Verify & review:** enter their encryption passphrase; Python authenticates/decrypts and checks the checksum, then the browser checks SHA-256 before displaying a preview or download.
- **Accept into vault:** the API re-verifies the stored object before adding its first immutable version and owner key envelope. It reuses the existing encrypted object.
- **Reject:** mark it rejected without adding it to the vault. Ciphertext is retained locally in this prototype.
- **Close link:** immediately block further submissions. Previously received submissions remain reviewable.

Each link accepts up to 20 submissions (10 by default), up to 25 MiB per file and 100 MiB total. Limits include accepted and rejected submissions; rejection does not reset a public link's quota. Expiry, quotas, and owner-only review are enforced in Python, including simultaneous requests. Inbox creation, receipt, preview, acceptance, rejection, and closure are audited. Integrity verification does not imply malware scanning.

Localhost links work on this computer. Sharing with someone on another computer requires deploying the app behind HTTPS. The existing passphrase-per-download flow is unchanged by this update.

The optional `test/inbox-browser.mjs` smoke test requires Playwright and a separate seeded server (`PORT=3011 DATA_DIR=/private/tmp/securevault-inbox-browser ./run.sh`). Run with `node test/inbox-browser.mjs`; `PLAYWRIGHT_MODULE` can select an already installed Playwright module. This browser test covers guest encryption, owner review/acceptance, a verified download, and link closure.

## Interface and architecture walkthrough

The brown storage-console interface takes layout inspiration from [MinIO's console](https://www.min.io/blog/new-minio-console): persistent navigation, an object table, filtering, and explicit object details. SecureVault uses a local espresso/ivory/copper palette, native SVG icons, file-type filters and sorting, and responsive file views. No external fonts or frontend assets are downloaded.

Open **How it works → Read the illustrated implementation guide**, or visit **http://localhost:3000/guide.html**. The standalone `public/guide.html` also opens directly from disk. It explains the implemented owner, anonymous uploader, signed-in uploader, and shared-recipient flows, with an interactive request trace, key hierarchy, storage map, and print/PDF support. It explicitly distinguishes current behavior from the session-unlock improvement discussed earlier.

The optional `test/ui-browser.mjs` check covers the redesigned login, upload, filters/sorting, version restore, sharing, verified download, audit, inbox and mobile overflow. Use an isolated seeded server on port 3012. It writes desktop/mobile screenshots to `/private/tmp/securevault-ui-screenshots` by default.
