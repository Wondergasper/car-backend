"""
Entity verification helpers for organization signup.
"""
from __future__ import annotations

from typing import Any, Dict

import httpx

from app.core.config import get_settings

settings = get_settings()


async def verify_entity(company_name: str, rc_number: str) -> Dict[str, Any]:
    """
    Try to verify the entity against GLEIF when configured.
    Falls back to an unverified result when the upstream service is unavailable.
    """
    result: Dict[str, Any] = {
        "verification_provider": "gleif",
        "verification_status": "unverified",
        "verification_entity_name": company_name,
        "verification_reference": rc_number,
        "verification_detail": "Verification pending upstream lookup.",
    }

    if not settings.GLEIF_API_BASE_URL:
        result["verification_detail"] = "GLEIF API is not configured in this environment."
        return result

    try:
        async with httpx.AsyncClient(timeout=settings.GLEIF_TIMEOUT_SECONDS) as client:
            response = await client.get(
                f"{settings.GLEIF_API_BASE_URL.rstrip('/')}/lei-records",
                params={"filter[entity.legalName]": company_name, "page[size]": 5},
            )
            response.raise_for_status()
    except Exception as exc:
        result["verification_detail"] = f"GLEIF lookup failed: {exc}"
        return result

    payload = response.json() if response.content else {}
    records = payload.get("data") or []
    matched = None
    rc_number_normalized = rc_number.strip().lower()
    company_name_normalized = company_name.strip().lower()

    for record in records:
        entity = (record or {}).get("attributes", {}).get("entity", {})
        legal_name = ((entity.get("legalName") or {}).get("name") or "").strip()
        other_names = entity.get("otherEntityNames") or []
        registration = entity.get("registeredAs") or ""
        aliases = [legal_name, *(n.get("name", "") for n in other_names if isinstance(n, dict))]

        if registration and registration.strip().lower() == rc_number_normalized:
            matched = record
            break
        if any(alias.strip().lower() == company_name_normalized for alias in aliases if alias):
            matched = record
            break

    if matched:
        entity = matched.get("attributes", {}).get("entity", {})
        result.update(
            {
                "verification_status": "verified",
                "verification_entity_name": ((entity.get("legalName") or {}).get("name") or company_name),
                "verification_reference": entity.get("registeredAs") or matched.get("id") or rc_number,
                "verification_detail": "Matched against GLEIF legal-entity records.",
            }
        )
    else:
        result["verification_detail"] = "No matching GLEIF entity record was found."

    return result
