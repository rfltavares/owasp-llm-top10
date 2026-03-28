# LLM02 Insecure Output Handling - Applications

This directory contains practical applications and tools for exploring, testing, and preventing insecure output handling vulnerabilities in Large Language Model applications.

##  IMPORTANT DISCLAIMER

**These tools are for EDUCATIONAL and AUTHORIZED security testing ONLY!**

- Only use on systems you own or have explicit written permission to test
- Unauthorized security testing is ILLEGAL and unethical
- Follow responsible disclosure practices
- Comply with all local laws and regulations
- Respect application terms of service

##  Applications Overview

### 1. `output_security_scanner.py`
**Purpose:** Comprehensive scanner for detecting insecure output handling vulnerabilities

**Features:**
- Multi-vulnerability detection (XSS, SQL Injection, Command Injection, Path Traversal, SSRF)
- Payload-based testing with comprehensive attack vectors
- Pattern-based detection with confidence scoring
- Severity assessment and risk calculation
- Detailed security reporting and recommendations

**Usage:**
```bash
python output_security_scanner.py
```

**Integration Example:**
```python
from output_security_scanner import OutputSecurityScanner

scanner = OutputSecurityScanner()

# Test LLM output for vulnerabilities
findings = scanner.scan_llm_output("Your LLM output here")

# Test with custom payloads
def your_llm_function(prompt):
    return llm.generate(prompt)

findings = scanner.test_with_payloads(your_llm_function)
```

### 2. `secure_output_filter.py`
**Purpose:** Real-time filtering and sanitization system for LLM outputs

**Features:**
- Comprehensive filtering rules for all major vulnerability types
- Context-aware sanitization (HTML, SQL, Command, URL contexts)
- Configurable security levels (strict, moderate, permissive)
- Whitelist support for legitimate content
- Multiple encoding methods (HTML, URL, JavaScript, CSS)
- Security policy generation and recommendations

**Usage:**
```bash
python secure_output_filter.py
```

**Integration Example:**
```python
from secure_output_filter import SecureOutputFilter, FilterAction

filter_system = SecureOutputFilter(security_level="high")

# Filter LLM output before use
result = filter_system.filter_output(llm_response, context="html")

if result.action == FilterAction.BLOCK:
    return "Content blocked for security reasons"
elif result.action == FilterAction.SANITIZE:
    return result.filtered_content
else:
    return result.original_content
```

### 3. `output_validation_framework.py`
**Purpose:** Comprehensive framework for validating and securing LLM outputs

**Features:**
- Modular validator architecture (Security, Quality, Compliance)
- Configurable validation levels and rules
- Custom validator support
- Comprehensive reporting and scoring
- Validation history and statistics
- GDPR and HIPAA compliance checking

**Usage:**
```bash
python output_validation_framework.py
```

**Integration Example:**
```python
from output_validation_framework import OutputValidationFramework, ValidationLevel

framework = OutputValidationFramework(ValidationLevel.STRICT)

# Validate LLM output
results = framework.validate_output(llm_response)
assessment = framework.get_overall_assessment(results)

if assessment['overall_result'] == ValidationResult.FAIL:
    # Handle failed validation
    pass
```

### 4. `interactive_output_security_lab.py`
**Purpose:** Hands-on learning environment for output security vulnerabilities

**Features:**
- Interactive scenarios covering all major vulnerability types
- Progressive difficulty levels (Beginner to Advanced)
- Vulnerable vs secure system comparisons
- Real-time vulnerability detection and analysis
- Code examples showing vulnerable and secure implementations
- Built-in hints, test payloads, and learning objectives

**Usage:**
```bash
python interactive_output_security_lab.py
```

**Learning Scenarios:**
1. **Cross-Site Scripting (XSS)** - HTML output vulnerabilities
2. **SQL Injection** - Database query construction issues
3. **Command Injection** - System command execution risks
4. **Server-Side Request Forgery (SSRF)** - URL handling vulnerabilities
5. **Path Traversal** - File system access issues

## 🛠️ Installation and Setup

### Prerequisites
```bash
# Python 3.7+
pip install requests
pip install html5lib  # For advanced HTML parsing
pip install urllib3   # For URL handling
```

### Quick Start
1. Clone or download the applications
2. Install dependencies
3. Configure target systems (for testing tools)
4. Run the desired application

### Environment Setup
```bash
# Create virtual environment
python -m venv output_security_env
source output_security_env/bin/activate  # Linux/Mac
# or
output_security_env\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage Examples

### Scanning LLM Output for Vulnerabilities
```python
from output_security_scanner import OutputSecurityScanner, VulnerabilityType

scanner = OutputSecurityScanner()

# Test specific LLM output
llm_output = "Here's some HTML: <script>alert('XSS')</script>"
findings = scanner.scan_llm_output(llm_output)

for finding in findings:
    print(f"Vulnerability: {finding.vulnerability_type.value}")
    print(f"Severity: {finding.severity}")
    print(f"Evidence: {finding.evidence}")
    print(f"Recommendation: {finding.recommendation}")
```

### Real-time Output Filtering
```python
from secure_output_filter import SecureOutputFilter

# Initialize filter with high security
filter_system = SecureOutputFilter(security_level="high")

def secure_llm_endpoint(user_input):
    # Get LLM response
    llm_response = your_llm.generate(user_input)
    
    # Filter output before returning
    result = filter_system.filter_output(llm_response, context="html")
    
    if result.action == FilterAction.BLOCK:
        return {"error": "Content blocked for security reasons"}
    
    return {"response": result.filtered_content}
```

### Comprehensive Output Validation
```python
from output_validation_framework import OutputValidationFramework

framework = OutputValidationFramework()

def validate_llm_output(content):
    # Run all validators
    results = framework.validate_output(content)
    
    # Get overall assessment
    assessment = framework.get_overall_assessment(results)
    
    return {
        'is_safe': assessment['overall_result'] != ValidationResult.FAIL,
        'score': assessment['average_score'],
        'recommendations': assessment['recommendations']
    }
```

### Learning with Interactive Lab
```bash
# Start the interactive lab
python interactive_output_security_lab.py

# Follow the guided scenarios:
# 1. Select a vulnerability type (XSS, SQL Injection, etc.)
# 2. Learn about the vulnerability through examples
# 3. Test payloads against vulnerable and secure systems
# 4. Compare outputs and understand the differences
```

## 🔍 Vulnerability Detection Capabilities

### Cross-Site Scripting (XSS)
- **Script tags:** `<script>`, `</script>`
- **Event handlers:** `onclick`, `onload`, `onerror`
- **JavaScript protocols:** `javascript:`
- **HTML injection:** `<iframe>`, `<object>`, `<embed>`
- **Encoded payloads:** URL and HTML encoded scripts

### SQL Injection
- **Union attacks:** `UNION SELECT`
- **Boolean-based:** `OR '1'='1`
- **Time-based:** `SLEEP()`, `WAITFOR`
- **Stacked queries:** `; DROP TABLE`
- **Stored procedures:** `xp_cmdshell`, `sp_executesql`

### Command Injection
- **Command chaining:** `;`, `&&`, `||`
- **Command substitution:** `` `command` ``, `$(command)`
- **Pipe operations:** `|`
- **File operations:** `cat`, `type`, `dir`
- **Network commands:** `wget`, `curl`, `nc`

### Server-Side Request Forgery (SSRF)
- **Internal networks:** `127.0.0.1`, `localhost`, `192.168.x.x`
- **Cloud metadata:** `169.254.169.254`
- **Protocol abuse:** `file://`, `ftp://`, `gopher://`
- **Port scanning:** Various internal ports

### Path Traversal
- **Directory traversal:** `../`, `..\\`
- **Encoded traversal:** `%2e%2e%2f`
- **Null byte injection:** `%00`
- **System files:** `/etc/passwd`, `C:\Windows\System32`

### Information Disclosure
- **API keys:** OpenAI, GitHub, AWS patterns
- **Credentials:** Password patterns
- **PII:** SSN, credit cards, emails
- **System information:** Configuration details

## Security Controls Implementation

### Input Validation
```python
def validate_llm_input(user_input):
    # Length limits
    if len(user_input) > 10000:
        raise ValueError("Input too long")
    
    # Character restrictions
    if re.search(r'[<>"\']', user_input):
        raise ValueError("Invalid characters detected")
    
    return True
```

### Output Encoding
```python
import html
import urllib.parse

def encode_for_context(content, context):
    if context == "html":
        return html.escape(content)
    elif context == "url":
        return urllib.parse.quote(content)
    elif context == "javascript":
        return json.dumps(content)
    else:
        return content
```

### Content Security Policy (CSP)
```python
def generate_csp_header():
    return {
        'Content-Security-Policy': 
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "media-src 'self'; "
        "frame-src 'none'"
    }
```

### Parameterized Queries
```python
def safe_database_query(user_input):
    # SECURE: Use parameterized queries
    query = "SELECT * FROM users WHERE name = ?"
    return execute_query(query, [user_input])

def unsafe_database_query(user_input):
    # VULNERABLE: String concatenation
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return execute_query(query)
```

### Safe Command Execution
```python
import subprocess
import shlex

def safe_command_execution(user_input):
    # SECURE: Use subprocess with argument list
    safe_input = shlex.quote(user_input)
    result = subprocess.run(['ls', '-la', safe_input], 
                          capture_output=True, text=True)
    return result.stdout

def unsafe_command_execution(user_input):
    # VULNERABLE: Shell injection possible
    import os
    os.system(f"ls -la {user_input}")
```

## 📊 Security Testing Methodology

### 1. **Static Analysis**
- Pattern-based detection of dangerous content
- Regular expression matching for known attack vectors
- Code review for insecure output handling patterns

### 2. **Dynamic Testing**
- Payload injection and response analysis
- Behavioral testing with malicious inputs
- Real-time vulnerability detection

### 3. **Contextual Analysis**
- Output context determination (HTML, SQL, Command, etc.)
- Context-specific vulnerability assessment
- Appropriate encoding validation

### 4. **Compliance Checking**
- GDPR personal data detection
- HIPAA health information identification
- Industry-specific regulation compliance

## Learning Path

### Beginner Level
1. **Start with Interactive Lab** - Learn basic concepts through guided scenarios
2. **Understand XSS** - Most common web vulnerability
3. **Practice with Safe Environments** - Use provided vulnerable systems

### Intermediate Level
1. **SQL Injection** - Database security fundamentals
2. **Command Injection** - System-level security risks
3. **Output Filtering** - Implement basic security controls

### Advanced Level
1. **SSRF and Advanced Attacks** - Complex vulnerability chains
2. **Custom Validation Framework** - Build comprehensive security systems
3. **Security Architecture** - Design secure LLM applications

## Performance Considerations

### Filtering Performance
```python
# Optimize for high-throughput scenarios
class OptimizedFilter:
    def __init__(self):
        # Compile regex patterns once
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.patterns.items()
        }
    
    def fast_filter(self, content):
        # Use compiled patterns for better performance
        for name, pattern in self.compiled_patterns.items():
            if pattern.search(content):
                return self.handle_match(name, content)
        return content
```

### Caching Strategies
```python
from functools import lru_cache

class CachedValidator:
    @lru_cache(maxsize=1000)
    def validate_cached(self, content_hash):
        # Cache validation results for repeated content
        return self.validate(content_hash)
```

## Customization and Extension

### Adding Custom Validators
```python
from output_validation_framework import BaseValidator, ValidationReport

class CustomBusinessValidator(BaseValidator):
    def __init__(self):
        super().__init__("CustomBusinessValidator")
    
    def validate(self, content, context=None):
        # Implement custom business logic
        report = ValidationReport(content=content)
        
        # Your custom validation logic here
        if "confidential" in content.lower():
            report.failed_rules.append("confidential_content")
        
        return report

# Add to framework
framework.add_validator(CustomBusinessValidator())
```

### Custom Security Rules
```python
# Add custom security patterns
custom_rules = {
    'custom_threat': [
        {
            'pattern': r'your_custom_pattern',
            'action': FilterAction.BLOCK,
            'severity': 'high',
            'description': 'Custom threat detected'
        }
    ]
}

filter_system.filter_rules.update(custom_rules)
```

## Educational Resources

### OWASP Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

### Practice Platforms
- [WebGoat](https://owasp.org/www-project-webgoat/) - OWASP's vulnerable web application
- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web Application
- [bWAPP](http://www.itsecgames.com/) - Buggy Web Application

### Research Papers
- "Output Encoding and Injection Prevention" (OWASP)
- "Context-Aware Output Sanitization" (Security Research)
- "LLM Security: Output Handling Best Practices" (AI Security)

## Ethical Guidelines

### Responsible Use
1. **Authorization Required:** Only test systems you own or have permission to test
2. **Educational Purpose:** Use for learning and improving security
3. **Responsible Disclosure:** Report vulnerabilities through proper channels
4. **No Harm:** Don't use for malicious purposes or to cause damage

### Legal Considerations
- Unauthorized testing may violate Computer Fraud and Abuse Act (CFAA)
- Respect terms of service for applications and platforms
- Follow local cybersecurity laws and regulations
- Consider privacy implications of security testing

### Best Practices
- Start with your own systems or dedicated test environments
- Document all testing activities and findings
- Share knowledge to improve overall security
- Contribute to defensive research and open-source tools

## Contributing

### How to Contribute
1. **Bug Reports:** Report issues or false positives in detection
2. **New Vulnerabilities:** Submit detection patterns for emerging threats
3. **Performance Improvements:** Optimize scanning and filtering performance
4. **Documentation:** Improve explanations and add examples

### Contribution Guidelines
- Ensure all contributions are for defensive/educational purposes
- Include comprehensive testing and validation
- Follow coding standards and documentation requirements
- Provide clear examples and use cases

---

**Remember: The goal is to improve LLM application security through education and responsible research. Use these tools ethically and help build more secure AI systems! 🔒**
