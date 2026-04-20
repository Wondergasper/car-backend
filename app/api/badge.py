"""
Public Compliance Badge endpoint.
Returns an embeddable SVG badge showing the org's current compliance score.
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.db.session import get_db
from app.models.database import Organization, Audit, AuditStatus

router = APIRouter()


def _score_color(score: int) -> str:
    if score >= 80:
        return "#22c55e"   # green
    elif score >= 60:
        return "#f59e0b"   # amber
    else:
        return "#ef4444"   # red


def _build_svg(org_name: str, score: int, color: str) -> str:
    label = "NDPA Compliant"
    label_w = 110
    score_text = f"{score}%"
    score_w = 54
    total_w = label_w + score_w

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <defs>
    <linearGradient id="g" x2="0" y2="100%">
      <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
      <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <mask id="m">
      <rect width="{total_w}" height="20" rx="3" fill="#fff"/>
    </mask>
  </defs>
  <g mask="url(#m)">
    <rect width="{label_w}" height="20" fill="#555"/>
    <rect x="{label_w}" width="{score_w}" height="20" fill="{color}"/>
    <rect width="{total_w}" height="20" fill="url(#g)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,sans-serif" font-size="110">
    <text x="{label_w // 2 * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(0.1)" textLength="{(label_w - 10) * 10}">{label}</text>
    <text x="{label_w // 2 * 10}" y="140" transform="scale(0.1)" textLength="{(label_w - 10) * 10}">{label}</text>
    <text x="{(label_w + score_w // 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(0.1)" textLength="{(score_w - 6) * 10}">{score_text}</text>
    <text x="{(label_w + score_w // 2) * 10}" y="140" transform="scale(0.1)" textLength="{(score_w - 6) * 10}">{score_text}</text>
  </g>
</svg>"""


@router.get("/badge/{org_slug}", response_class=Response)
async def get_compliance_badge(
    org_slug: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns an embeddable SVG compliance badge.
    Embed with: <img src="https://your-host/badge/{org-slug}" />
    """
    org_result = await db.execute(
        select(Organization).where(Organization.slug == org_slug)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Get latest completed audit score
    audit_result = await db.execute(
        select(Audit)
        .where(
            Audit.org_id == org.id,
            Audit.status == AuditStatus.COMPLETED,
        )
        .order_by(Audit.created_at.desc())
        .limit(1)
    )
    latest_audit = audit_result.scalar_one_or_none()

    score = latest_audit.compliance_score if latest_audit else 0
    color = _score_color(score)
    svg = _build_svg(org.name, score, color)

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "no-cache, max-age=0",
            "X-Org": org.name,
        },
    )
