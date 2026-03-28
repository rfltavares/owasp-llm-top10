#!/usr/bin/env python3
"""
Plugin Security Scanner
"""

import re
from typing import List, Dict, Any

class PluginSecurityScanner:
    def __init__(self):
        self.security_checks = self.load_security_checks()
    
    def load_security_checks(self) -> Dict[str, Any]:
        return {
            'input_validation': {
                'patterns': [r'request\.get\([^)]+\)', r'input\(', r'raw_input\('],
                'severity': 'high',
                'description': 'Missing input validation'
            },
            'authentication': {
                'patterns': [r'@app\.route.*methods=\[.*POST.*\]', r'def\s+\w+\([^)]*\):'],
                'severity': 'critical',
                'description': 'Missing authentication check'
            },
            'sql_injection': {
                'patterns': [r'execute\([^)]*%s', r'\.format\(', r'f".*{.*}"'],
                'severity': 'critical',
                'description': 'Potential SQL injection'
            },
            'command_injection': {
                'patterns': [r'os\.system\(', r'subprocess\.call\(', r'eval\(', r'exec\('],
                'severity': 'critical',
                'description': 'Command injection risk'
            }
        }
    
    def scan_plugin(self, plugin_code: str, plugin_name: str = "unknown") -> Dict[str, Any]:
        """Scan plugin code for security vulnerabilities"""
        
        vulnerabilities = []
        
        for check_name, check_info in self.security_checks.items():
            for pattern in check_info['patterns']:
                matches = list(re.finditer(pattern, plugin_code))
                
                if matches:
                    vulnerabilities.append({
                        'check': check_name,
                        'severity': check_info['severity'],
                        'description': check_info['description'],
                        'occurrences': len(matches),
                        'pattern': pattern
                    })
        
        # Calculate security score
        critical_count = sum(1 for v in vulnerabilities if v['severity'] == 'critical')
        high_count = sum(1 for v in vulnerabilities if v['severity'] == 'high')
        
        security_score = max(0, 100 - (critical_count * 30) - (high_count * 15))
        
        return {
            'plugin_name': plugin_name,
            'vulnerabilities': vulnerabilities,
            'security_score': security_score,
            'risk_level': self.calculate_risk_level(security_score),
            'recommendation': self.generate_recommendation(vulnerabilities)
        }
    
    def calculate_risk_level(self, score: float) -> str:
        """Calculate risk level from security score"""
        if score >= 80:
            return 'low'
        elif score >= 60:
            return 'medium'
        elif score >= 40:
            return 'high'
        else:
            return 'critical'
    
    def generate_recommendation(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate security recommendations"""
        if not vulnerabilities:
            return "Plugin appears secure"
        
        critical = [v for v in vulnerabilities if v['severity'] == 'critical']
        if critical:
            return "BLOCK: Critical vulnerabilities found - do not use"
        
        return "REVIEW: Security issues found - manual review required"

def main():
    print("Plugin Security Scanner")
    print("=" * 25)
    
    scanner = PluginSecurityScanner()
    
    # Test plugin code
    test_code = """
def process_request(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    os.system(f"echo {user_input}")
    return execute(query)
    """
    
    result = scanner.scan_plugin(test_code, "test_plugin")
    
    print(f"Plugin: {result['plugin_name']}")
    print(f"Security Score: {result['security_score']}/100")
    print(f"Risk Level: {result['risk_level'].upper()}")
    print(f"\nVulnerabilities: {len(result['vulnerabilities'])}")
    
    for vuln in result['vulnerabilities']:
        print(f"  - [{vuln['severity']}] {vuln['description']}")
    
    print(f"\nRecommendation: {result['recommendation']}")

if __name__ == "__main__":
    main()
