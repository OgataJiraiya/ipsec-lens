"""Same-origin Render preview with the existing API and built React assets."""
from pathlib import Path

from fastapi import HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.main import create_app

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "frontend" / "dist"
FIXTURES = {
    ("weak", "weak.pcap"), ("weak", "telemetry.json"),
    ("strong", "strong.pcap"), ("strong", "telemetry.json"),
}

def create_preview_app(dist: Path = DIST, data_dir: Path | None = None):
    app = create_app(data_dir=data_dir, preview_hosted=True)
    app.mount("/assets", StaticFiles(directory=dist / "assets", check_dir=False), name="preview-assets")

    @app.get("/fixtures/{scenario}/{name}")
    def fixture(scenario: str, name: str):
        if (scenario, name) not in FIXTURES:
            raise HTTPException(404, "Fixture not found")
        path = ROOT / "demo" / scenario / name
        return FileResponse(path, filename=name, headers={
            "X-Content-Type-Options": "nosniff", "Cache-Control": "public, max-age=3600"})

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str):
        if path in ("api", "fixtures", "assets") or path.startswith(("api/", "fixtures/", "assets/")) or "." in path:
            raise HTTPException(404, "Page not found")
        return FileResponse(dist / "index.html", headers={"Cache-Control": "no-store"})

    return app


app = create_preview_app()
