import asyncio
import json
from app.services.fix_generator import FixGenerationService
from app.core.rules_engine import ComplianceFinding

async def test_gemini():
    print("Testing Google Gemini Integration...")
    service = FixGenerationService()
    
    if not service.use_gemini:
        print("WARNING: Gemini is not active (check your GOOGLE_API_KEY in .env). Falling back to templates.")
    else:
        print("Gemini is active! Generating fix plan...")

    finding = ComplianceFinding(
        rule_id="RULE-123",
        article="Article 24",
        title="Unencrypted BVN Data Found",
        severity="high",
        description="We found raw bank verification numbers in the 'customers' table without any encryption at rest.",
        recommendation="Implement AES-256 encryption.",
        remediation_template="Use cryptography library to encrypt BVN columns.",
        evidence={"table": "customers", "sample": "222333444"}
    )
    
    plan = await service.generate_fix(finding, {"company_name": "Test Bank"})
    
    print("\n--- GENERATED REMEDIATION PLAN ---")
    print(f"Title: {plan.document_title}")
    print(f"Type: {plan.remediation_type}")
    print(f"Source: {plan.template_used}")
    print(f"Effort: {plan.estimated_effort}")
    print("\nContent Snippet:")
    print(plan.document_content[:200] + "...")
    print("\nImplementation Steps:")
    for step in plan.implementation_steps[:3]:
        print(f"- {step}")

if __name__ == "__main__":
    asyncio.run(test_gemini())
