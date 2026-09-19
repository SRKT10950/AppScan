# AppScan — on-premises Salesforce code analysis

A working first version of an independent, SonarQube-inspired Salesforce scan dashboard. Runs on Ubuntu Server using Docker Compose. No SonarQube server, paid service, cloud account, or GitHub integration required. The app is MIT licensed; PMD and container dependencies retain their own licenses. This is not a SonarSource product or a complete SonarQube replacement.

## What it does

- Accepts Salesforce DX or Metadata API source ZIPs.
- Runs real PMD 7.17.0 Apex security, error-prone, performance, and design rules.
- Detects issues such as missing CRUD checks and potential SOQL injection using PMD.
- Checks selected XML metadata for broad permissions, disabled protocol security, HTTP endpoints, and system-context flows. Metadata findings use line 1 (component-level review).
- Includes a heuristic for possible hardcoded credentials; that heuristic withholds matched values.
- Compares current and baseline components, including Apex source/sidecar files and LWC/Aura bundles.
- Generates `package.xml` for added/modified components and `destructiveChanges.xml` for deleted components.
- Offers searchable findings, severity filters, quality gates, a scan history, and downloadable JSON/Markdown reports and XML manifests.
- Requires authentication for scans and reports. Credentials stay in browser memory until refresh/sign-out.
- Keeps scan results in SQLite on a persistent Docker volume. Uploaded source stays in memory; temporary Apex files are removed after PMD. No source is executed or sent to a remote scanning service.

Initial image build downloads dependencies from Debian, Docker Hub, and GitHub. Runtime scanning does not require internet access. To deploy offline, build on a connected compatible machine, use `docker save`, transfer the image, and `docker load`; then run `docker compose up -d --no-build` with a local `.env`.

## Ubuntu Server installation

Prerequisite: Docker Engine with the Docker Compose plugin. Follow the official Ubuntu guide:
https://docs.docker.com/engine/install/ubuntu/

Extract the source bundle and run:

```bash
unzip appscan-onprem.zip
cd appscan
chmod +x setup.sh
./setup.sh
```

The script creates `.env` with a random admin password, builds the image, and starts the container. If your account cannot access Docker, use an account with Docker permissions or run `sudo ./setup.sh` (Docker access is equivalent to root access).

Read credentials locally:

```bash
cat .env
```

App URL: **http://127.0.0.1:8088** on the server. Username: **admin**. Password: `APPSCAN_PASSWORD` in `.env`.

By default, the service binds to server loopback. From Windows PowerShell or another computer, open an SSH tunnel and leave it running:

```powershell
ssh -N -L 8088:127.0.0.1:8088 ubuntu@YOUR_SERVER_IP
```

Then open **http://localhost:8088** in your browser. Replace `ubuntu` with your server login.

For persistent access through a domain, put an HTTPS reverse proxy in front of port 8088. Basic authentication must travel over HTTPS or an SSH tunnel. For a reverse proxy running in Docker, attach it to an appropriate network and configure the upstream accordingly; its `127.0.0.1` is not the host. Do not expose this HTTP service directly to the public internet. Apply login rate limits at the reverse proxy for shared deployments.

To change ports, edit `APPSCAN_PORT` in `.env`, then run `docker compose up -d`. `APPSCAN_BIND` controls the host interface. Set a unique password of at least 16 characters. Restart after changing it. Never commit `.env`.

Start on boot uses `restart: unless-stopped`; ensure the Docker service is enabled:

```bash
sudo systemctl enable docker
docker compose ps
docker compose logs --tail=100 appscan
```

## First scan

The `examples` folder contains intentionally insecure demo snapshots; never deploy them to an org.

1. Sign in and enter a project name.
2. Choose `examples/current.zip` as Current source.
3. Choose `examples/baseline.zip` as Baseline source.
4. Set the Metadata API version supported by your target org (default is explicitly 64.0, not automatically the newest).
5. Click **Run analysis**.
6. Expect a failed gate with `ApexCRUDViolation`, `ApexSOQLInjection`, and `PrivilegedPermission` findings.
7. Metadata changes should include a modified Apex class, an added permission set, and a deleted custom field.
8. Download the report ZIP.

For your own project, create snapshots in your repository:

```bash
git archive --format=zip --output=/tmp/appscan-baseline.zip BASE_COMMIT
git archive --format=zip --output=/tmp/appscan-current.zip HEAD
```

Use actual commit IDs or branch names for `BASE_COMMIT`. `git archive` includes committed tracked files only. The app does not clone repositories, store Git credentials, connect to Salesforce, or post PR comments.

Without a baseline, all supported current components are treated as added and no deletions are inferred. The security scan always examines all current Apex files, not just changed files. The gate is therefore not a “new code only” gate.

## Gates and coverage

| Result | Meaning |
| --- | --- |
| INCOMPLETE | PMD unavailable/failed/timed out, a processing error, or invalid inspected XML. Never accept this as clean. |
| FAIL | Analysis completed and at least one High or Critical finding exists. |
| PASS | No blocking findings under implemented checks; not proof of security or deployment correctness. |

PMD priority 1 maps to Critical; priority 2 to High; priority 3 to Medium; 4/5 to Low. Security rules are at least High. XML privilege/endpoint checks are High, system-context flow review is Medium, and possible hardcoded credentials are High. Findings may be false positives. Review them; the app does not fix code or suppress findings automatically.

Supported mappings include Apex classes/triggers, Visualforce pages/components, Flow, PermissionSet, Profile, Layout, CustomTab, CustomApplication, PermissionSetGroup, FlexiPage, RemoteSiteSetting, NamedCredential, ExternalCredential, GlobalValueSet, StandardValueSet, CustomMetadata, StaticResource, CustomObject, LWC/Aura bundles, and decomposed object fields/validation rules/record types/list views/field sets/compact layouts/web links/business processes/sharing reasons.

LWC/Aura and Visualforce have change mapping but no JavaScript or Visualforce security engine in this version. XML checking covers selected risks, not effective access across an org. CustomLabels, reports, dashboards, translations, sharing rules, email templates, and other unmapped types are not supported in generated manifests. Unmapped code/XML-like files are shown in Coverage; arbitrary assets/configuration files are not exhaustively classified.

Mapping is path-based and expects conventional Salesforce source folders. Ambiguous duplicate components across package directories are rejected. Files compare by SHA-256: whitespace changes count. Renames appear as delete/add. Monolithic `.object` files compare as a whole CustomObject rather than individual children. Bundle changes are grouped into one metadata member. API version is user selected.

**Review manifests before use.** The download contains manifests only, not a deployable delta source package. It does not resolve dependencies, profile/permission-set merge behavior, deployment ordering, package namespaces, or org compatibility. Unsupported metadata is omitted and flagged. Validate in a sandbox, include the required source, and review destructive changes carefully. No deployment is performed by AppScan.

## Operations and limits

Designed as a single-admin, single-instance service for a small team or home server. Suggested starting allocation: 2 CPU cores and 2 GiB RAM (configured in Compose); actual use depends on source size. Java heap is capped at 768 MiB. Suitable to try on a 4-core/16-GB Ubuntu server alongside other services; measure resource use under your actual workload.

- One scan runs at a time, up to three queued/running requests total.
- Each ZIP: 20 MiB compressed, 100 MiB expanded, 2 MiB per file, 10,000 entries. Large static resources must be excluded or the limits deliberately adjusted after capacity review.
- PMD timeout: 180 seconds; two PMD analysis threads.
- Maximum request body: 58 MiB, including base64 overhead.
- Symlinks, path traversal, duplicate paths, and encrypted archives are rejected.
- All scan results remain until an administrator removes/restores the data volume. No in-app delete/retention policy yet; monitor disk use. The UI shows the latest 100 scans.
- Interrupted queued/running scans become failed on restart and must be resubmitted.
- No per-project authorization, multiuser accounts, SSO, audit trail, scan scheduler, PR integration, suppression workflow, trends, dependency scanner, or Salesforce org retrieval.
- Scan reports contain filenames, identifiers, metadata members, and PMD messages; treat them as confidential. Source ZIPs are not stored, but reports are not guaranteed to be free of sensitive identifiers.
- The HTTP service is intended to sit behind SSH/HTTPS, not serve as an internet-facing hardened application server.

Back up onto a separate physical machine/disk. To produce a consistent SQLite backup:

```bash
docker compose exec -T appscan python -c 'import sqlite3; s=sqlite3.connect("/data/appscan.db"); d=sqlite3.connect("/data/backup.db"); s.backup(d); d.close(); s.close()'
docker compose cp appscan:/data/backup.db ./appscan-backup.db
```

Copy that backup and a protected copy of `.env` to your backup machine. For restoration, stop AppScan, restore the database into the volume with UID/GID 10001 ownership, remove stale WAL/SHM files for the replaced database, and restart. Do not run multiple containers against the same database.

## Local development and tests

Requires Python 3.12 (no third-party Python packages). For full Apex scans, also install Java 17 and the pinned PMD 7.17.0 distribution. Set `PMD_BIN` to its `bin/pmd` executable.

```bash
python -m unittest discover -s tests -v
export DATA_DIR="$PWD/data"
export APPSCAN_USER=admin
# Set APPSCAN_PASSWORD securely in your local shell (16+ characters).
export PMD_BIN=/path/to/pmd-bin-7.17.0/bin/pmd
python -m app.server
```

Development URL: http://localhost:8080. Development server binds on all interfaces; use local firewall controls. PMD installation missing? Apex scans explicitly become INCOMPLETE; metadata-only scans still work.

The Dockerfile pins the PMD ZIP version and the SHA-256 observed for the tested upstream distribution. If upgrading PMD, update both build arguments and retest the rules/report schema. Base OS/image packages are not fully reproducible locks and require your normal patching process.

## API

All `/api/*` endpoints require an HTTP Basic Authorization header. Public endpoints serve static sign-in assets and `/healthz` (liveness only).

- `POST /api/scans`: JSON `project`, `api_version`, `current` (base64 ZIP), optional `baseline` (base64 ZIP). Returns HTTP 202 with `id`.
- `GET /api/scans`: latest 100 scan summaries.
- `GET /api/scans/{id}`: status and results.
- `GET /api/scans/{id}/report.zip`: completed report and manifests.

Use an HTTPS or SSH-protected connection and poll the scan endpoint until status is `complete` or `failed`. A `complete` scan can still have gate `INCOMPLETE`; check both fields in CI. Queue full returns 429. Invalid archives are reported asynchronously as failed scans.

## Validation performed for this release

- 15 automated tests pass: archive defenses, component diff/manifests, XML checks, secret redaction, missing-PMD behavior, API authentication, scan workflow, report download.
- Real PMD 7.17.0 with Java 17 detected Apex CRUD and SOQL-injection findings in the included demo; no engine errors.
- Live authenticated HTTP scan with real PMD, baseline comparison, and ZIP report download passed.
- Python compilation, static asset/security-header checks, and browser JavaScript syntax checks pass.
- Browser visual testing was blocked because the Chromium download timed out.
- Docker image build was not tested in the creation environment because Docker was unavailable. Build and smoke-test on your Ubuntu host before operational use.

## References

- PMD: https://pmd.github.io/
- Pinned PMD release: https://github.com/pmd/pmd/releases/tag/pmd_releases%2F7.17.0
- Docker on Ubuntu: https://docs.docker.com/engine/install/ubuntu/
