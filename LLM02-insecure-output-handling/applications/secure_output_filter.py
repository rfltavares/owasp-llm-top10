#!/usr/bin/env python3
"""
Secure Output Filter
Comprehensive filtering and sanitization system for LLM outputs
"""

import re
import html
import json
import urllib.parse
import base64
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class FilterAction(Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"
    WARN = "warn"

@dataclass
class FilterResult:
    action: FilterAction
    original_content: str
    filtered_content: str
    detected_threats: List[str]
    confidence: float
    recommendations: List[str]

class SecureOutputFilter:
    def __init__(self, security_level: str = "high"):
        self.security_level = security_level
        self.filter_rules = self.load_filter_rules()
        self.sanitization_rules = self.load_sanitization_rules()
        self.whitelist_patterns = self.load_whitelist_patterns()
        self.encoding_methods = {
            'html': self.html_encode,
            'url': self.url_encode,
            'javascript': self.javascript_encode,
            'css': self.css_encode
        }
    
    def load_filter_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load comprehensive filtering rules"""
        
        return {
            'xss_prevention': [
                {
                    'pattern': r'<script[^>]*>.*?</script>',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'Script tag detected'
                },
                {
                    'pattern': r'javascript:',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'JavaScript protocol detected'
                },
                {
                    'pattern': r'on\w+\s*=\s*["\'][^"\']*["\']',
                    'action': FilterAction.SANITIZE,
                    'severity': 'high',
                    'description': 'Event handler attribute detected'
                },
                {
                    'pattern': r'<iframe[^>]*>',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Iframe tag detected'
                },
                {
                    'pattern': r'<object[^>]*>',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Object tag detected'
                },
                {
                    'pattern': r'<embed[^>]*>',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Embed tag detected'
                }
            ],
            
            'sql_injection_prevention': [
                {
                    'pattern': r'(union\s+select|drop\s+table|delete\s+from|insert\s+into)',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'SQL injection pattern detected'
                },
                {
                    'pattern': r'(exec\s*\(|execute\s*\(|sp_executesql)',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'SQL execution command detected'
                },
                {
                    'pattern': r'(xp_cmdshell|xp_regwrite|xp_regread)',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'Dangerous SQL extended procedure detected'
                }
            ],
            
            'command_injection_prevention': [
                {
                    'pattern': r'(;\s*(rm|del|format)\s+)',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'Dangerous system command detected'
                },
                {
                    'pattern': r'(\|\s*(nc|netcat|wget|curl)\s+)',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Network command detected'
                },
                {
                    'pattern': r'(`[^`]*`|\$\([^)]*\))',
                    'action': FilterAction.SANITIZE,
                    'severity': 'high',
                    'description': 'Command substitution detected'
                },
                {
                    'pattern': r'(&&|\|\|)\s*(rm|del|format|shutdown)',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'Chained dangerous command detected'
                }
            ],
            
            'path_traversal_prevention': [
                {
                    'pattern': r'\.\.[\\/].*\.\.[\\/]',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Path traversal pattern detected'
                },
                {
                    'pattern': r'(\/etc\/passwd|\/etc\/shadow|C:\\Windows\\System32)',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'Sensitive system path detected'
                },
                {
                    'pattern': r'%2e%2e%2f',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Encoded path traversal detected'
                }
            ],
            
            'code_injection_prevention': [
                {
                    'pattern': r'(eval\s*\(|exec\s*\(|Function\s*\()',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'Code evaluation function detected'
                },
                {
                    'pattern': r'(__import__|getattr|setattr|delattr)',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Python introspection function detected'
                },
                {
                    'pattern': r'(require\s*\(|import\s+os|import\s+subprocess)',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Dangerous import statement detected'
                }
            ],
            
            'ssrf_prevention': [
                {
                    'pattern': r'(http://127\.0\.0\.1|http://localhost|http://0\.0\.0\.0)',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Local network access detected'
                },
                {
                    'pattern': r'http://169\.254\.169\.254',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'Cloud metadata service access detected'
                },
                {
                    'pattern': r'(file://|ftp://|gopher://)',
                    'action': FilterAction.BLOCK,
                    'severity': 'high',
                    'description': 'Non-HTTP protocol detected'
                }
            ],
            
            'information_disclosure_prevention': [
                {
                    'pattern': r'(password\s*[:=]\s*[^\s]+|api[_\s]?key\s*[:=]\s*[^\s]+)',
                    'action': FilterAction.SANITIZE,
                    'severity': 'high',
                    'description': 'Credential pattern detected'
                },
                {
                    'pattern': r'(sk-[A-Za-z0-9]{48}|ghp_[A-Za-z0-9]{36})',
                    'action': FilterAction.BLOCK,
                    'severity': 'critical',
                    'description': 'API key pattern detected'
                },
                {
                    'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                    'action': FilterAction.SANITIZE,
                    'severity': 'high',
                    'description': 'SSN pattern detected'
                },
                {
                    'pattern': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
                    'action': FilterAction.SANITIZE,
                    'severity': 'high',
                    'description': 'Credit card pattern detected'
                }
            ]
        }
    
    def load_sanitization_rules(self) -> Dict[str, Any]:
        """Load sanitization rules and replacement patterns"""
        
        return {
            'html_sanitization': {
                'allowed_tags': ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
                'allowed_attributes': ['class', 'id'],
                'remove_tags': ['script', 'iframe', 'object', 'embed', 'form', 'input', 'textarea', 'select'],
                'remove_attributes': ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur', 'href', 'src']
            },
            
            'content_replacements': {
                # Credential sanitization
                r'password\s*[:=]\s*[^\s]+': 'password: [REDACTED]',
                r'api[_\s]?key\s*[:=]\s*[^\s]+': 'api_key: [REDACTED]',
                r'sk-[A-Za-z0-9]{48}': '[API_KEY_REDACTED]',
                r'ghp_[A-Za-z0-9]{36}': '[GITHUB_TOKEN_REDACTED]',
                
                # PII sanitization
                r'\b\d{3}-\d{2}-\d{4}\b': '[SSN_REDACTED]',
                r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b': '[CARD_NUMBER_REDACTED]',
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[EMAIL_REDACTED]',
                
                # System path sanitization
                r'\/etc\/passwd': '[SYSTEM_FILE_REDACTED]',
                r'C:\\Windows\\System32': '[SYSTEM_PATH_REDACTED]',
                
                # Command sanitization
                r'(rm|del|format)\s+-[rf]*\s+[\/\\]': '[DANGEROUS_COMMAND_REMOVED]',
                r'(wget|curl)\s+http[s]?://[^\s]+': '[NETWORK_COMMAND_REMOVED]'
            }
        }
    
    def load_whitelist_patterns(self) -> List[str]:
        """Load patterns that should be allowed even if they match filter rules"""
        
        return [
            r'<code>.*</code>',  # Code examples in documentation
            r'```.*```',  # Code blocks in markdown
            r'example\.com',  # Example domains
            r'localhost.*example',  # Example localhost usage
            r'test.*password',  # Test/example passwords
        ]
    
    def filter_output(self, content: str, context: str = "general") -> FilterResult:
        """Main filtering function"""
        
        detected_threats = []
        filtered_content = content
        action = FilterAction.ALLOW
        confidence = 0.0
        recommendations = []
        
        # Check whitelist first
        if self.is_whitelisted(content):
            return FilterResult(
                action=FilterAction.ALLOW,
                original_content=content,
                filtered_content=content,
                detected_threats=[],
                confidence=0.0,
                recommendations=[]
            )
        
        # Apply filter rules
        for category, rules in self.filter_rules.items():
            for rule in rules:
                matches = list(re.finditer(rule['pattern'], content, re.IGNORECASE | re.MULTILINE))
                
                if matches:
                    threat_info = f"{rule['description']} ({rule['severity']})"
                    detected_threats.append(threat_info)
                    
                    # Update action based on rule severity and current action
                    rule_action = rule['action']
                    if rule_action == FilterAction.BLOCK:
                        action = FilterAction.BLOCK
                        confidence = max(confidence, 0.9)
                    elif rule_action == FilterAction.SANITIZE and action != FilterAction.BLOCK:
                        action = FilterAction.SANITIZE
                        confidence = max(confidence, 0.7)
                    
                    # Apply sanitization if needed
                    if rule_action == FilterAction.SANITIZE:
                        filtered_content = self.sanitize_content(filtered_content, rule['pattern'])
        
        # Generate recommendations
        recommendations = self.generate_recommendations(detected_threats, action)
        
        # Final content processing based on action
        if action == FilterAction.BLOCK:
            filtered_content = "[CONTENT BLOCKED FOR SECURITY REASONS]"
        elif action == FilterAction.SANITIZE:
            filtered_content = self.apply_comprehensive_sanitization(filtered_content)
        
        return FilterResult(
            action=action,
            original_content=content,
            filtered_content=filtered_content,
            detected_threats=detected_threats,
            confidence=confidence,
            recommendations=recommendations
        )
    
    def is_whitelisted(self, content: str) -> bool:
        """Check if content matches whitelist patterns"""
        
        for pattern in self.whitelist_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def sanitize_content(self, content: str, threat_pattern: str) -> str:
        """Sanitize content by removing or replacing threats"""
        
        # Remove the specific threat pattern
        sanitized = re.sub(threat_pattern, '[REMOVED]', content, flags=re.IGNORECASE)
        
        return sanitized
    
    def apply_comprehensive_sanitization(self, content: str) -> str:
        """Apply comprehensive sanitization rules"""
        
        sanitized = content
        
        # Apply content replacements
        for pattern, replacement in self.sanitization_rules['content_replacements'].items():
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        # HTML sanitization
        sanitized = self.sanitize_html(sanitized)
        
        # URL sanitization
        sanitized = self.sanitize_urls(sanitized)
        
        return sanitized
    
    def sanitize_html(self, content: str) -> str:
        """Sanitize HTML content"""
        
        html_rules = self.sanitization_rules['html_sanitization']
        
        # Remove dangerous tags
        for tag in html_rules['remove_tags']:
            pattern = f'<{tag}[^>]*>.*?</{tag}>'
            content = re.sub(pattern, '', content, flags=re.IGNORECASE | re.DOTALL)
            
            # Also remove self-closing tags
            pattern = f'<{tag}[^>]*/?>'
            content = re.sub(pattern, '', content, flags=re.IGNORECASE)
        
        # Remove dangerous attributes
        for attr in html_rules['remove_attributes']:
            pattern = f'{attr}\\s*=\\s*["\'][^"\']*["\']'
            content = re.sub(pattern, '', content, flags=re.IGNORECASE)
        
        # HTML encode remaining content
        content = html.escape(content)
        
        return content
    
    def sanitize_urls(self, content: str) -> str:
        """Sanitize URLs in content"""
        
        # Pattern to match URLs
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[^\s<>"\']+\.[a-z]{2,}[^\s<>"\']*'
        
        def validate_and_sanitize_url(match):
            url = match.group(0)
            
            # Block dangerous protocols
            dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:', 'ftp:']
            for protocol in dangerous_protocols:
                if url.lower().startswith(protocol):
                    return '[BLOCKED_URL]'
            
            # Block local/internal URLs
            local_patterns = [
                r'127\.0\.0\.1', r'localhost', r'0\.0\.0\.0',
                r'169\.254\.169\.254',  # AWS metadata
                r'192\.168\.\d+\.\d+', r'10\.\d+\.\d+\.\d+', r'172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+'
            ]
            
            for pattern in local_patterns:
                if re.search(pattern, url):
                    return '[INTERNAL_URL_BLOCKED]'
            
            # URL encode the URL for safety
            return urllib.parse.quote(url, safe=':/?#[]@!$&\'()*+,;=')
        
        return re.sub(url_pattern, validate_and_sanitize_url, content, flags=re.IGNORECASE)
    
    def generate_recommendations(self, threats: List[str], action: FilterAction) -> List[str]:
        """Generate security recommendations based on detected threats"""
        
        recommendations = []
        
        if action == FilterAction.BLOCK:
            recommendations.append("Content blocked due to security threats. Review and sanitize before use.")
        
        if any('XSS' in threat or 'script' in threat.lower() for threat in threats):
            recommendations.extend([
                "Implement Content Security Policy (CSP)",
                "Use proper output encoding for HTML context",
                "Validate and sanitize all user inputs"
            ])
        
        if any('SQL' in threat or 'injection' in threat.lower() for threat in threats):
            recommendations.extend([
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege for database access"
            ])
        
        if any('command' in threat.lower() for threat in threats):
            recommendations.extend([
                "Avoid executing system commands with user input",
                "Use safe APIs instead of shell commands",
                "Implement strict input validation and sandboxing"
            ])
        
        if any('credential' in threat.lower() or 'key' in threat.lower() for threat in threats):
            recommendations.extend([
                "Implement credential detection and redaction",
                "Use secure credential management systems",
                "Regular audit for exposed credentials"
            ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def html_encode(self, content: str) -> str:
        """HTML encode content"""
        return html.escape(content)
    
    def url_encode(self, content: str) -> str:
        """URL encode content"""
        return urllib.parse.quote(content)
    
    def javascript_encode(self, content: str) -> str:
        """JavaScript encode content"""
        # Basic JavaScript encoding
        encoded = content.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
        encoded = encoded.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        return encoded
    
    def css_encode(self, content: str) -> str:
        """CSS encode content"""
        # Basic CSS encoding
        encoded = re.sub(r'[^a-zA-Z0-9\s]', lambda m: f'\\{ord(m.group(0)):x}', content)
        return encoded
    
    def create_security_policy(self) -> Dict[str, Any]:
        """Create comprehensive security policy configuration"""
        
        return {
            'content_security_policy': {
                'default-src': "'self'",
                'script-src': "'self' 'unsafe-inline'",
                'style-src': "'self' 'unsafe-inline'",
                'img-src': "'self' data: https:",
                'connect-src': "'self'",
                'font-src': "'self'",
                'object-src': "'none'",
                'media-src': "'self'",
                'frame-src': "'none'"
            },
            
            'input_validation': {
                'max_length': 10000,
                'allowed_characters': r'[a-zA-Z0-9\s\.\,\!\?\-\_\(\)\[\]\{\}]',
                'blocked_patterns': [
                    r'<script[^>]*>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'eval\s*\(',
                    r'exec\s*\('
                ]
            },
            
            'output_sanitization': {
                'html_encoding': True,
                'url_encoding': True,
                'remove_dangerous_tags': True,
                'remove_event_handlers': True,
                'validate_urls': True
            },
            
            'monitoring': {
                'log_blocked_content': True,
                'alert_on_critical_threats': True,
                'track_threat_patterns': True,
                'generate_security_reports': True
            }
        }

def main():
    """Main function to demonstrate secure output filtering"""
    
    print("Secure Output Filter Demo")
    print("=" * 30)
    
    filter_system = SecureOutputFilter(security_level="high")
    
    # Test cases
    test_cases = [
        # XSS attempts
        "Here's some HTML: <script>alert('XSS')</script>",
        "Click here: <a href='javascript:alert(\"XSS\")'>Link</a>",
        
        # SQL injection
        "Query: SELECT * FROM users WHERE id = '1' OR '1'='1'",
        "Database command: '; DROP TABLE users; --",
        
        # Command injection
        "Execute: ls -la; rm -rf /",
        "Run command: $(whoami)",
        
        # Path traversal
        "File path: ../../../etc/passwd",
        "Access: C:\\Windows\\System32\\config\\sam",
        
        # Credential exposure
        "API key: sk-1234567890abcdef1234567890abcdef12345678",
        "Password: admin123",
        
        # Safe content
        "This is normal text content.",
        "Here's a code example: <code>print('hello')</code>",
    ]
    
    for i, test_content in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_content[:50]}...")
        
        result = filter_system.filter_output(test_content)
        
        print(f"Action: {result.action.value.upper()}")
        print(f"Confidence: {result.confidence:.2f}")
        
        if result.detected_threats:
            print(f"Threats: {', '.join(result.detected_threats)}")
        
        if result.action != FilterAction.ALLOW:
            print(f"Filtered: {result.filtered_content[:100]}...")
        
        if result.recommendations:
            print(f"Recommendations: {result.recommendations[0]}")
    
    # Generate security policy
    policy = filter_system.create_security_policy()
    print(f"\nSecurity Policy Generated:")
    print(json.dumps(policy, indent=2))

if __name__ == "__main__":
    main()