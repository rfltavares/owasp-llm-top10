#!/usr/bin/env python3
"""
PII and Sensitive Information Scanner
"""

import re
from typing import List, Dict, Any

class PIIScanner:
    def __init__(self):
        self.patterns = self.load_patterns()
    
    def load_patterns(self) -> Dict[str, Dict[str, Any]]:
        return {
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'severity': 'critical',
                'description': 'Social Security Number'
            },
            'credit_card': {
                'pattern': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
                'severity': 'critical',
                'description': 'Credit Card Number'
            },
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': 'high',
                'description': 'Email Address'
            },
            'phone': {
                'pattern': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'severity': 'medium',
                'description': 'Phone Number'
            },
            'api_key': {
                'pattern': r'(sk-[A-Za-z0-9]{48}|ghp_[A-Za-z0-9]{36})',
                'severity': 'critical',
                'description': 'API Key'
            },
            'password': {
                'pattern': r'password\s*[:=]\s*[^\s]+',
                'severity': 'critical',
                'description': 'Password'
            }
        }
    
    def scan_text(self, text: str) -> Dict[str, Any]:
        """Scan text for PII and sensitive information"""
        
        findings = []
        
        for pii_type, info in self.patterns.items():
            matches = list(re.finditer(info['pattern'], text, re.IGNORECASE))
            
            for match in matches:
                findings.append({
                    'type': pii_type,
                    'severity': info['severity'],
                    'description': info['description'],
                    'match': match.group(),
                    'position': match.span(),
                    'redacted': self.redact_match(match.group(), pii_type)
                })
        
        return {
            'text_length': len(text),
            'findings': findings,
            'risk_level': self.calculate_risk_level(findings),
            'redacted_text': self.redact_text(text, findings)
        }
    
    def redact_match(self, match: str, pii_type: str) -> str:
        """Redact sensitive information"""
        
        redaction_map = {
            'ssn': '[SSN_REDACTED]',
            'credit_card': '[CARD_REDACTED]',
            'email': '[EMAIL_REDACTED]',
            'phone': '[PHONE_REDACTED]',
            'api_key': '[API_KEY_REDACTED]',
            'password': 'password: [REDACTED]'
        }
        
        return redaction_map.get(pii_type, '[REDACTED]')
    
    def redact_text(self, text: str, findings: List[Dict[str, Any]]) -> str:
        """Redact all sensitive information from text"""
        
        redacted = text
        
        # Sort findings by position (reverse order to maintain positions)
        sorted_findings = sorted(findings, key=lambda x: x['position'][0], reverse=True)
        
        for finding in sorted_findings:
            start, end = finding['position']
            redacted = redacted[:start] + finding['redacted'] + redacted[end:]
        
        return redacted
    
    def calculate_risk_level(self, findings: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level"""
        
        if not findings:
            return 'none'
        
        critical_count = sum(1 for f in findings if f['severity'] == 'critical')
        high_count = sum(1 for f in findings if f['severity'] == 'high')
        
        if critical_count > 0:
            return 'critical'
        elif high_count > 2:
            return 'high'
        elif high_count > 0:
            return 'medium'
        else:
            return 'low'

def main():
    print("PII Scanner")
    print("=" * 15)
    
    scanner = PIIScanner()
    
    # Test text
    test_text = """
    Contact: john.doe@example.com
    SSN: 123-45-6789
    Phone: 555-123-4567
    API Key: sk-1234567890abcdef1234567890abcdef12345678
    """
    
    result = scanner.scan_text(test_text)
    
    print(f"Findings: {len(result['findings'])}")
    print(f"Risk Level: {result['risk_level'].upper()}")
    print("\nDetected PII:")
    for finding in result['findings']:
        print(f"  - [{finding['severity']}] {finding['description']}: {finding['match']}")
    
    print(f"\nRedacted Text:\n{result['redacted_text']}")

if __name__ == "__main__":
    main()
