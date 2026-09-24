# SIH submission preview on Render

This branch builds a limited public preview. `main` remains the canonical release.
The preview shows Overview, New Analysis, Protocol Analysis, Security Assessment,
Findings, and Reports. JSON export, deletion, and the other seven views remain in
the normal local application. The frontend flag controls presentation; the backend
flag blocks JSON export and deletion on the public preview API.

## Render Web Service configuration

| Setting | Value |
| --- | --- |
| Service type | Web Service |
| Instance | Free |
| Repository branch | `submission-preview` |
| Root directory | repository root |
| Runtime | Docker |
| Dockerfile path | `./Dockerfile.preview` |
| Docker build context | `.` |
| Docker command override | blank (use Dockerfile `CMD`) |
| Health check path | `/api/health` |

Set these Render environment variables exactly:

```text
VITE_SUBMISSION_PREVIEW=true
IPSECLENS_SUBMISSION_PREVIEW=true
IPSECLENS_MAX_UPLOAD=8388608
IPSECLENS_MAX_PACKETS=100000
IPSECLENS_MAX_FLOWS=512
```

Render supplies `PORT`; the image defaults to `10000` for local container runs.
The startup command is `uvicorn deploy.render_app:app --host 0.0.0.0 --port ${PORT:-10000}`.
The image sets `IPSECLENS_DATA_DIR=/app/runtime`, an ephemeral writable directory.
The frontend flag is baked into the Docker build, so changing its runtime value alone
does not change the compiled UI. Rebuild to change the UI preview mode. The backend
flag is read when the API app starts. With `IPSECLENS_SUBMISSION_PREVIEW=true`,
`DELETE /api/analyses/{identity}` and `GET /api/analyses/{identity}/export` return
HTTP 403 with `Disabled in submission preview`; uploads force `retain_capture=false`
even when the client submits `true`. Do not set `IPSECLENS_ABSTENTION`; the canonical
threshold remains `0.60`.

The Node 24 build produces `frontend/dist`; Python 3.13 runs the existing FastAPI
routes and serves the same-origin SPA and four downloadable synthetic fixture files.
PDF reporting uses Cairo, Pango, GDK Pixbuf, and DejaVu fonts in the runtime image.
The preview image packages the validated `models/classifier.json` artifact and
`models/classifier.sha256` digest. Its Docker build verifies their SHA-256 match and
copies both into the runtime image; it does not retrain the classifier. The normal
`make release-check` model regeneration and integrity gate remain unchanged. The
runtime uses an unprivileged user, disables raw capture retention even for direct API
calls, and does not run capture, VPN lab, or Docker commands. No raw capture download
endpoint is provided.

The public preview uses controlled synthetic fixtures. The full local prototype supports broader analysis.

Recommended judge workflow:

1. Open preview.
2. Click **Analyze Weak VPN** on Overview (or New Analysis).
3. Review Overview.
4. Open Protocol Analysis.
5. Open Security Assessment.
6. Open Findings.
7. Open Reports and download Executive/Technical HTML or PDF.
8. Optionally run **Analyze Strong VPN** from New Analysis for comparison.

Each button runs the real backend pipeline with the matching bundled capture and
validated telemetry, MODERN policy and no raw capture retention. Results are
persisted normally and labelled SYNTHETIC FIXTURE. Expected canonical results are
weak: 30.5 / HARDEN and strong: 97.5 / ACCEPT, both with coverage 1.0.
Nothing runs automatically on page load. Both buttons disable during analysis;
temporary failures show a safe retry message.

`POST /api/preview/demo/{scenario}` exists only with the backend preview flag.
Only `weak` and `strong` are accepted; no paths or URLs are inputs. The existing
two-slot intake limit and same-origin POST protection also apply to demo requests.
There is no job queue. The preview image includes all five provenance manifests
required by the existing analyzer, while offering only the two approved scenarios.

Manual upload is labelled **Advanced · bundled fixture upload** (Option A): the
supported public workflow uses bundled synthetic fixtures only. Download links for
captures and matching telemetry remain available; use MODERN policy when uploading.
This is a UI scope notice, not a server-side digest restriction.
Preview analyses may disappear after a restart. The public preview has no user
accounts: analysis history and reports are shared by visitors. Use only the bundled
synthetic fixtures on this public service; do not upload private captures or endpoint
telemetry. The backend preview flag blocks export and deletion while keeping capture
upload, telemetry import, analysis history, Overview, Protocol Analysis, Security
Assessment, Findings, and HTML/PDF reports available. Without the backend flag, the
normal local API keeps its existing export, deletion, and capture retention behavior.

## Local checks

```sh
make test
make release-check
(cd frontend && VITE_SUBMISSION_PREVIEW=true npm test -- --run src/test/Preview.test.tsx)
(cd frontend && VITE_SUBMISSION_PREVIEW=true npm run build)
docker build -f Dockerfile.preview -t ipseclens-submission-preview .
docker run --rm -p 10000:10000 -e PORT=10000 -e IPSECLENS_SUBMISSION_PREVIEW=true ipseclens-submission-preview
```

With the container running, check `/api/health`, `/`, a frontend fallback route,
the four `/fixtures/` downloads, and HTML/PDF reports after an analysis.
