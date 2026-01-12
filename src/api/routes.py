# src/api/routes.py
import os
import uuid
import io
import csv

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse, Response

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from src.models.schemas import ScanRequest, ScanResponse
from src.core.detector import analyze_email
from src.services.header_analyzer import analyze_headers
from src.services.attachment_scanner import scan_attachments

from src.models.quarantine import QuarantineRecord
from src.storage.quarantine_store import save_record, get_record

# ✅ Explicit AUTH ENFORCEMENT as requested:
#   - All protected routes now explicitly use Depends(get_current_user)
#   - OTP gating and RBAC are applied AFTER authentication
from src.auth.dependencies import get_current_user
from src.auth.models import UserRecord, UserRole

router = APIRouter()

MAX_EMAIL_CHARS = int(os.getenv("MAX_EMAIL_CHARS", "20000"))
OTP_ENFORCED = os.getenv("OTP_ENFORCED", "true").lower() in ("1", "true", "yes", "y")


def _enforce_otp_if_required(user: UserRecord) -> None:
    """
    Enforce OTP verification for sensitive operations.
    Assumes UserRecord exposes fields similar to:
      - otp_enabled: bool
      - otp_verified: bool  (or is_otp_verified / is_2fa_verified)
    If your field name differs, update the checks below to match your model.
    """
    otp_enabled = bool(getattr(user, "otp_enabled", False))
    otp_verified = bool(
        getattr(user, "otp_verified", False)
        or getattr(user, "is_otp_verified", False)
        or getattr(user, "is_2fa_verified", False)
    )

    if OTP_ENFORCED and otp_enabled and not otp_verified:
        raise HTTPException(status_code=403, detail="2FA verification required")


def _enforce_admin(user: UserRecord) -> None:
    """
    Enforce admin role for privileged operations.
    Assumes UserRecord.role exists and is comparable to UserRole.admin or "admin".
    """
    role_val = getattr(user, "role", None)
    if role_val == UserRole.admin:
        return
    if isinstance(role_val, str) and role_val.lower() == "admin":
        return
    raise HTTPException(status_code=403, detail="Admin privileges required")


@router.get("/health")
def health():
    # Health is intentionally public for uptime checks / monitoring.
    return {"status": "ok", "service": "phishing-detector", "version": "0.1.0"}


# ✅ Protected scan feature:
# - Explicit JWT enforcement: Depends(get_current_user)
# - OTP gating enforced when otp_enabled=True (configurable via OTP_ENFORCED)
@router.post("/scan-email", response_model=ScanResponse)
def scan_email(
    payload: ScanRequest,
    user: UserRecord = Depends(get_current_user),
):
    _enforce_otp_if_required(user)

    scan_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())

    # Basic DoS prevention
    if len(payload.email_text) > MAX_EMAIL_CHARS:
        rec = QuarantineRecord(
            scan_id=scan_id,
            verdict="REJECTED",
            score=0,
            reasons=[f"Email content too large (max {MAX_EMAIL_CHARS} chars)"],
            urls=[],
            status="STORED",
        )
        save_record(rec)

        return ScanResponse(
            verdict="REJECTED",
            score=0,
            reasons=rec.reasons,
            urls=[],
            header_score=0,
            header_findings=[],
            attachment_score=0,
            attachment_findings=[],
            scan_id=scan_id,
            request_id=request_id,
        )

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

    # Final classification (consistent thresholds)
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
# ✅ Admin-only export:
# - Explicit JWT enforcement: Depends(get_current_user)
# - OTP gating (if enabled)
# - RBAC admin role enforcement
@router.get("/reports/{scan_id}.csv")
def export_csv(
    scan_id: str,
    user: UserRecord = Depends(get_current_user),
):
    _enforce_otp_if_required(user)
    _enforce_admin(user)

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
def export_pdf(
    scan_id: str,
    user: UserRecord = Depends(get_current_user),
):
    _enforce_otp_if_required(user)
    _enforce_admin(user)

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
