#!/usr/bin/env python3
"""
Supply Chain Security Scanner
"""

import re
import hashlib
from typing import List, Dict, Any

class SupplyChainScanner:
    def __init__(self):
        self.vulnerability_patterns = self.load_patterns()
    
    def load_patterns(self) -> Dict[str, List[str]]:
        return {
            'malicious_imports': [
                r'import\s+os',
                r'import\s+subprocess',
                r'import\s+socket',
                r'__import__\(',
            ],
            'network_access': [
                r'requests\.',
                r'urllib\.',
                r'http\.',
                r'socket\.',
            ],
            'file_operations': [
                r'open\(',
                r'file\(',
                r'write\(',
                r'os\.system',
            ]
        }
    
    def scan_dependency(self, package_name: str, source_code: str = "") -> Dict[str, Any]:
        """Scan dependency for security issues"""
        
        issues = []
        
        # Check package name for typosquatting
        if self.check_typosquatting(package_name):
            issues.append({
                'type': 'typosquatting',
                'severity': 'high',
                'description': 'Package name similar to popular package'
            })
        
        # Scan source code if available
        if source_code:
            for category, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, source_code):
                        issues.append({
                            'type': category,
                            'severity': 'medium',
                            'description': f'Found {category} pattern: {pattern}'
                        })
        
        return {
            'package': package_name,
            'issues': issues,
            'risk_score': len(issues) * 0.2,
            'recommendation': 'Review before use' if issues else 'Appears safe'
        }
    
    def check_typosquatting(self, package_name: str) -> bool:
        """Check for typosquatting"""
        
        popular_packages = [
            'tensorflow', 'pytorch', 'numpy', 'pandas', 
            'scikit-learn', 'transformers', 'openai'
        ]
        
        for popular in popular_packages:
            distance = self.levenshtein_distance(package_name.lower(), popular)
            if 0 < distance <= 2:
                return True
        
        return False
    
    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

def main():
    print("Supply Chain Scanner")
    print("=" * 20)
    
    scanner = SupplyChainScanner()
    
    # Test scan
    result = scanner.scan_dependency("tensorflaw", "import os\nimport requests")
    print(f"Package: {result['package']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Issues: {len(result['issues'])}")
    for issue in result['issues']:
        print(f"  - [{issue['severity']}] {issue['description']}")

if __name__ == "__main__":
    main()
