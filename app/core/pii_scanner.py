"""
PII Scanner - Detects Nigerian personal data identifiers.
Scans for BVN, NIN, phone numbers, emails, and other sensitive data.
"""
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class PIICategory(str, Enum):
    BVN = "bvn"
    NIN = "nin"
    PHONE = "phone"
    EMAIL = "email"
    DRIVERS_LICENSE = "drivers_license"
    VOTERS_ID = "voters_id"
    ADDRESS = "address"
    MEDICAL = "medical"
    FINANCIAL = "financial"
    BIOMETRIC = "biometric"


@dataclass
class PIIFinding:
    category: PIICategory
    value: str  # Masked for security
    location: str  # Table/column where found
    confidence: float  # 0.0 to 1.0
    risk_level: str  # low, medium, high, critical
    description: str


class PIIScanner:
    """
    Scans data for Nigerian personal identifiers.
    Used during compliance audits to detect PII exposure.
    """
    
    # Nigerian BVN (11 digits)
    BVN_PATTERN = re.compile(r'\b\d{11}\b')
    
    # Nigerian NIN (11 digits, starts with specific prefixes)
    NIN_PATTERN = re.compile(r'\b[0-9]{11}\b')
    
    # Nigerian phone numbers (various formats)
    PHONE_PATTERNS = [
        re.compile(r'\b(?:234|0)(?:[789][01]\d)\d{7}\b'),  # 070, 080, 081, 090, 091
        re.compile(r'\b\+234(?:[789][01]\d)\d{7}\b'),
    ]
    
    # Email addresses
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    # Nigerian driver's license (varies by state, typically 8-9 chars)
    DRIVERS_LICENSE_PATTERN = re.compile(r'\b[A-Z]{2,3}\d{6,8}\b')
    
    # Patterns requiring context (to reduce false positives)
    CONTEXT_PATTERNS = {
        PIICategory.BVN: {
            'keywords': ['bvn', 'bank verification', 'verification number'],
            'pattern': BVN_PATTERN,
        },
        PIICategory.NIN: {
            'keywords': ['nin', 'national identity', 'identity number', 'id number'],
            'pattern': NIN_PATTERN,
        },
    }
    
    def __init__(self):
        self.findings: List[PIIFinding] = []
    
    def scan_text(self, text: str, location: str = "unknown") -> List[PIIFinding]:
        """Scan a text string for PII."""
        self.findings = []
        
        # Scan for emails
        self._scan_emails(text, location)
        
        # Scan for phone numbers
        self._scan_phones(text, location)
        
        # Scan for BVN (with context check)
        self._scan_bvn(text, location)
        
        # Scan for NIN (with context check)
        self._scan_nin(text, location)
        
        return self.findings
    
    def scan_dict(self, data: Dict[str, Any], location: str = "unknown") -> List[PIIFinding]:
        """Scan a dictionary for PII in values."""
        self.findings = []
        
        for key, value in data.items():
            current_location = f"{location}/{key}"
            
            if isinstance(value, str):
                self.scan_text(value, current_location)
            elif isinstance(value, dict):
                self.scan_dict(value, current_location)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        self.scan_text(item, f"{current_location}[{i}]")
                    elif isinstance(item, dict):
                        self.scan_dict(item, f"{current_location}[{i}]")
        
        return self.findings
    
    def _scan_emails(self, text: str, location: str):
        """Extract email addresses."""
        for match in self.EMAIL_PATTERN.finditer(text):
            email = match.group()
            masked = self._mask_email(email)
            self.findings.append(PIIFinding(
                category=PIICategory.EMAIL,
                value=masked,
                location=location,
                confidence=1.0,  # Regex is definitive
                risk_level="medium",
                description=f"Email address found: {masked}"
            ))
    
    def _scan_phones(self, text: str, location: str):
        """Extract Nigerian phone numbers."""
        for pattern in self.PHONE_PATTERNS:
            for match in pattern.finditer(text):
                phone = match.group()
                masked = self._mask_phone(phone)
                self.findings.append(PIIFinding(
                    category=PIICategory.PHONE,
                    value=masked,
                    location=location,
                    confidence=0.9,
                    risk_level="medium",
                    description=f"Phone number found: {masked}"
                ))
    
    def _scan_bvn(self, text: str, location: str):
        """Extract BVN numbers (requires context verification)."""
        # Check for context keywords
        text_lower = text.lower()
        has_context = any(kw in text_lower for kw in self.CONTEXT_PATTERNS[PIICategory.BVN]['keywords'])
        
        for match in self.BVN_PATTERN.finditer(text):
            number = match.group()
            
            # If no context, lower confidence
            confidence = 0.95 if has_context else 0.6
            
            if confidence >= 0.7:  # Only report if confident
                masked = self._mask_number(number)
                self.findings.append(PIIFinding(
                    category=PIICategory.BVN,
                    value=masked,
                    location=location,
                    confidence=confidence,
                    risk_level="critical",  # BVN is highly sensitive
                    description=f"BVN (Bank Verification Number) detected: {masked}"
                ))
    
    def _scan_nin(self, text: str, location: str):
        """Extract NIN numbers (requires context verification)."""
        text_lower = text.lower()
        has_context = any(kw in text_lower for kw in self.CONTEXT_PATTERNS[PIICategory.NIN]['keywords'])
        
        for match in self.NIN_PATTERN.finditer(text):
            number = match.group()
            
            # Additional validation: NIN has specific structure
            if self._validate_nin(number):
                confidence = 0.95 if has_context else 0.65
                
                if confidence >= 0.7:
                    masked = self._mask_number(number)
                    self.findings.append(PIIFinding(
                        category=PIICategory.NIN,
                        value=masked,
                        location=location,
                        confidence=confidence,
                        risk_level="critical",
                        description=f"NIN (National Identity Number) detected: {masked}"
                    ))
    
    def _validate_nin(self, number: str) -> bool:
        """Validate Nigerian NIN format."""
        # NIN is 11 digits, some validation rules apply
        if len(number) != 11:
            return False
        if not number.isdigit():
            return False
        # Additional validation logic can be added here
        return True
    
    def _mask_email(self, email: str) -> str:
        """Mask email for safe display."""
        parts = email.split('@')
        if len(parts) != 2:
            return "***@***.***"
        local = parts[0]
        domain = parts[1]
        masked_local = local[0] + "***" + local[-1] if len(local) > 2 else "***"
        domain_parts = domain.split('.')
        masked_domain = domain_parts[0][0] + "***." + domain_parts[-1]
        return f"{masked_local}@{masked_domain}"
    
    def _mask_phone(self, phone: str) -> str:
        """Mask phone number for safe display."""
        # Keep first 3 and last 2 chars
        if len(phone) >= 5:
            return phone[:3] + "*****" + phone[-2:]
        return "*****"
    
    def _mask_number(self, number: str) -> str:
        """Mask a number for safe display."""
        if len(number) >= 4:
            return number[:2] + "****" + number[-2:]
        return "****"
    
    def get_summary(self, findings: List[PIIFinding]) -> Dict[str, Any]:
        """Generate a summary of PII findings."""
        summary = {
            "total_findings": len(findings),
            "by_category": {},
            "by_risk_level": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "high_risk_locations": [],
        }
        
        for finding in findings:
            # Count by category
            category = finding.category.value
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
            
            # Count by risk level
            summary["by_risk_level"][finding.risk_level] += 1
            
            # Track high-risk locations
            if finding.risk_level in ["critical", "high"]:
                if finding.location not in summary["high_risk_locations"]:
                    summary["high_risk_locations"].append(finding.location)
        
        return summary
