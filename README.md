# VoxelLive 1.6 Approval Relay (required for public access requests)

This public service is only an approval relay, session checker, and preset-sharing store. Every user's TikTok listener, Minecraft WebSocket, event feed, and configuration remain on that user's own Android/Termux installation. The developer's `admin.py` console connects to this relay from the developer's Termux.

## Deploy requirements

- A public HTTPS domain.
- A persistent writable volume for the SQLite database. Do not use an ephemeral container filesystem.
- A strong random `VOXELLIVE_ADMIN_TOKEN` secret.
- Python 3.10+ (the Dockerfile uses Python 3.12).

The API uses Python's standard library; no cloud Python dependencies need to be installed.

## Docker Compose deployment

On a server you control:

```bash
cd cloud_api
cp .env.example .env
nano .env
```

Generate a random Admin token on a trusted machine:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put that value in `.env` as `VOXELLIVE_ADMIN_TOKEN`. Also verify `VOXELLIVE_DB_PATH=/data/voxellive-v16.sqlite3`. Keep `.env` private and never commit it to GitHub.

Start the service:

```bash
docker compose up -d --build
```

The Compose file binds the API to `127.0.0.1:8080` on the server and keeps SQLite in the named `voxellive-cloud-data` volume. Put a TLS-enabled reverse proxy (for example, Caddy or Nginx) in front of that port and forward HTTPS requests to `127.0.0.1:8080`. The reverse proxy must preserve the `/api/...` paths and must not cache API responses. Use the HTTPS domain in the VoxelLive client configuration.

For a managed Docker host, set the same environment variables in its secret/configuration panel and attach a persistent volume at `/data`. Configure its public HTTPS domain to route to container port `8080`.

## Verify

Open:

```text
https://your-api-domain.example/api/health
```

Expected response contains:

```json
{"ok": true, "service": "VoxelLive Approval Relay", "version": "1.6.0"}
```

Do not proceed until this health endpoint works over HTTPS.

## Configure VoxelLive clients

Each player copy needs the public HTTPS base URL (no trailing `/api/health`) in its local `cloud_api_url.txt`, for example:

```text
https://api.your-domain.example
```

The URL is public configuration, not a secret. Include your actual Cloud API URL in the ZIP you publish for users, or explain how they set it before running `server.py`.

## Configure the developer's Admin Termux

On the developer's own Termux, run `python admin.py` from the VoxelLive project folder. Enter:

- The same public HTTPS Cloud API base URL.
- The exact `VOXELLIVE_ADMIN_TOKEN` value configured on the cloud host.

The token is stored locally in `admin_config.json`, with restrictive file permissions where the platform supports them. Keep that file private and out of GitHub. If it leaks, replace `VOXELLIVE_ADMIN_TOKEN` on the cloud host and run `python admin.py --setup` to update the local configuration.

## Approval commands

```text
terima nama_pengguna
tolak nama_pengguna
daftar
bantuan
keluar
```

`terima {nama}` approves a matching pending request. `tolak {nama}` rejects a pending request or revokes an approved user. Names are matched exactly (case-insensitively); only one pending/approved request can hold a name at a time. Revocation invalidates that user's sessions. The user's local VoxelLive watchdog stops its TikTok and Minecraft connections shortly after revocation; it does not stop any other user's process or the relay.

## Security and operations

- Use HTTPS only. Do not route end users to the raw HTTP port.
- Treat `VOXELLIVE_ADMIN_TOKEN` as a high-privilege secret. Never put it in a public build, client config, README command line, screenshots, or GitHub Actions logs.
- Back up `/data/voxellive-v16.sqlite3` regularly. The database contains user display names, request states, sessions' token hashes, and shared preset payloads; it does not contain user passwords.
- The relay stores only SHA-256 hashes of request secrets and session tokens. It never receives or stores Minecraft WebSocket addresses/commands or TikTok credentials.
- The service fails closed when a request/session cannot be validated. A brief Cloud API outage pauses access checks; local watchdogs do not intentionally disconnect an active player solely because one validation request times out.
- Rate limits and name uniqueness are enforced by the API. Keep the relay updated and monitor its logs.
