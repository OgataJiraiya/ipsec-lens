import pytest
from backend.reporting.pdf import render_pdf, deny_resource


@pytest.mark.parametrize("kind",["executive","technical"])
def test_offline_pdf(strong_run,kind):
    assert render_pdf(strong_run,kind).startswith(b"%PDF-")


@pytest.mark.parametrize("url",["file:///etc/passwd","https://example.invalid","data:text/plain,sensitive"])
def test_pdf_resources_denied(url):
    with pytest.raises(ValueError):
        deny_resource(url)


def test_pdf_size_limit(strong_run,monkeypatch):
    monkeypatch.setattr("backend.reporting.pdf.MAX_PDF_HTML",10)
    with pytest.raises(ValueError):
        render_pdf(strong_run,"technical")


def test_pdf_api(client,strong):
    result=client.post("/api/analyses",files={"capture":("strong.pcap",strong.read_bytes())})
    identity=result.json()["analysis_id"]
    report=client.get(f"/api/analyses/{identity}/report/executive?format=pdf")
    assert report.status_code==200 and report.content.startswith(b"%PDF-")
    assert report.headers["content-type"]=="application/pdf"
