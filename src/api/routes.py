# src/api/routes.py
import os
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, Response

from src.models.schemas import ScanRequest, ScanResponse
from src.core.detector import analyze_email
from src.services.header_analyzer import analyze_headers
from src.services.attachment_scanner import scan_attachments
from src.models.quarantine import QuarantineRecord
from src.storage.quarantine_store import save_record, get_record

import csv
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

router = APIRouter()

MAX_EMAIL_CHARS = int(os.getenv("MAX_EMAIL_CHARS", "20000"))


@router.get("/health")
def health():
    return {"status": "ok", "service": "phishing-detector", "version": "0.1.0"}


@router.post("/scan-email", response_model=ScanResponse)
def scan_email(payload: ScanRequest):
    # Basic DoS prevention
    if len(payload.email_text) > MAX_EMAIL_CHARS:
        scan_id = str(uuid.uuid4())
        request_id = str(uuid.uuid4())
        return ScanResponse(
            verdict="REJECTED",
            score=0,
            reasons=[f"Email content too large (max {MAX_EMAIL_CHARS} chars)"],
            urls=[],
            header_score=0,
            header_findings=[],
            attachment_score=0,
            attachment_findings=[],
            scan_id=scan_id,
            request_id=request_id,
        )

    scan_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())

    # Core content analysis
    result = analyze_email(payload.email_text)
    total_score = int(result["score"])
    reasons = list(result["reasons"])
    urls = list(result["urls"])

    # Header analysis (optional)
    header_score = 0
    header_findings = []
    header_details = None
    if payload.email_headers:
        header_score, header_findings, header_details = analyze_headers(payload.email_headers)
        total_score += header_score
        reasons.extend(header_findings)

    # Attachment analysis (optional)
    attachment_score = 0
    attachment_findings = []
    attachment_details = None
    if payload.attachments:
        attachment_score, attachment_findings, attachment_details = scan_attachments(payload.attachments)
        total_score += attachment_score
        reasons.extend(attachment_findings)

    # Re-classify based on total score
    # Keep your same thresholds for consistency
    verdict = result["verdict"]
    if total_score >= 60:
        verdict = "PHISHING"
    elif total_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    if verdict == "SAFE" and not reasons:
        reasons = ["No suspicious indicators detected"]

    # Persist + quarantine decision
    status = "QUARANTINED" if verdict == "PHISHING" else "STORED"
    rec = QuarantineRecord(
        scan_id=scan_id,
        verdict=verdict,
        score=total_score,
        reasons=reasons,
        urls=urls,
        header_score=header_score,
        header_findings=header_findings,
        attachment_score=attachment_score,
        attachment_findings=attachment_findings,
        status=status,
        header_details=header_details,
        attachment_details=attachment_details,
    )
    save_record(rec)

    return ScanResponse(
        verdict=verdict,
        score=total_score,
        reasons=reasons,
        urls=urls,
        header_score=header_score,
        header_findings=header_findings,
        attachment_score=attachment_score,
        attachment_findings=attachment_findings,
        scan_id=scan_id,
        request_id=request_id,
    )


# ----------------------------
# Reports (CSV + PDF exports)
# ----------------------------

@router.get("/reports/{scan_id}.csv")
def export_csv(scan_id: str):
    rec = get_record(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["scan_id", rec.scan_id])
    writer.writerow(["created_at", rec.created_at.isoformat()])
    writer.writerow(["status", rec.status])
    writer.writerow(["verdict", rec.verdict])
    writer.writerow(["score", rec.score])

    writer.writerow([])
    writer.writerow(["urls"])
    for u in rec.urls:
        writer.writerow([u])

    writer.writerow([])
    writer.writerow(["reasons"])
    for r in rec.reasons:
        writer.writerow([r])

    writer.writerow([])
    writer.writerow(["header_score", rec.header_score])
    writer.writerow(["header_findings"])
    for f in rec.header_findings:
        writer.writerow([f])

    writer.writerow([])
    writer.writerow(["attachment_score", rec.attachment_score])
    writer.writerow(["attachment_findings"])
    for f in rec.attachment_findings:
        writer.writerow([f])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{scan_id}.csv"'},
    )


@router.get("/reports/{scan_id}.pdf")
def export_pdf(scan_id: str):
    rec = get_record(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    y = height - 50
    line = 14

    def draw(text: str):
        nonlocal y
        if y < 60:
            c.showPage()
            y = height - 50
        c.drawString(50, y, text[:110])
        y -= line

    draw("Phishing Detector Report")
    draw(f"Scan ID: {rec.scan_id}")
    draw(f"Created: {rec.created_at.isoformat()} UTC")
    draw(f"Status: {rec.status}")
    draw(f"Verdict: {rec.verdict}")
    draw(f"Score: {rec.score}")

    draw("")
    draw("URLs:")
    for u in rec.urls[:50]:
        draw(f"- {u}")

    draw("")
    draw("Reasons:")
    for r in rec.reasons[:100]:
        draw(f"- {r}")

    draw("")
    draw(f"Header Score: {rec.header_score}")
    for f in rec.header_findings[:50]:
        draw(f"- {f}")

    draw("")
    draw(f"Attachment Score: {rec.attachment_score}")
    for f in rec.attachment_findings[:50]:
        draw(f"- {f}")

    c.save()
    buf.seek(0)

    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{scan_id}.pdf"'},
    )
