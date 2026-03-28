#!/usr/bin/env python3
"""
Output Validation Framework
Comprehensive framework for validating and securing LLM outputs
"""

import re
import json
import time
import hashlib
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

class ValidationLevel(Enum):
    STRICT = "strict"
    MODERATE = "moderate"
    PERMISSIVE = "permissive"

class ValidationResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"

@dataclass
class ValidationRule:
    name: str
    description: str
    pattern: str
    severity: str
    action: str
    enabled: bool = True
    custom_validator: Optional[Callable] = None

@dataclass
class ValidationReport:
    content: str
    overall_result: ValidationResult
    passed_rules: List[str] = field(default_factory=list)
    failed_rules: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    processing_time: float = 0.0

class BaseValidator(ABC):
    """Base class for all validators"""
    
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
    
    @abstractmethod
    def validate(self, content: str, context: Dict[str, Any] = None) -> ValidationReport:
        pass

class SecurityValidator(BaseValidator):
    """Security-focused validator for dangerous content"""
    
    def __init__(self, validation_level: ValidationLevel = ValidationLevel.MODERATE):
        super().__init__("SecurityValidator")
        self.validation_level = validation_level
        self.security_rules = self.load_security_rules()
    
    def load_security_rules(self) -> List[ValidationRule]:
        """Load security validation rules"""
        
        rules = [
            # XSS Prevention
            ValidationRule(
                name="script_tag_detection",
                description="Detects script tags that could lead to XSS",
                pattern=r'<script[^>]*>.*?</script>',
                severity="critical",
                action="block"
            ),
            ValidationRule(
                name="javascript_protocol",
                description="Detects javascript: protocol usage",
                pattern=r'javascript:',
                severity="high",
                action="block"
            ),
            ValidationRule(
                name="event_handlers",
                description="Detects HTML event handlers",
                pattern=r'on\w+\s*=\s*["\'][^"\']*["\']',
                severity="high",
                action="sanitize"
            ),
            
            # SQL Injection Prevention
            ValidationRule(
                name="sql_injection_keywords",
                description="Detects SQL injection keywords",
                pattern=r'\b(union\s+select|drop\s+table|delete\s+from|insert\s+into|exec\s*\()\b',
                severity="critical",
                action="block"
            ),
            ValidationRule(
                name="sql_comments",
                description="Detects SQL comment patterns",
                pattern=r'(--|\#|/\*|\*/)',
                severity="medium",
                action="warn"
            ),
            
            # Command Injection Prevention
            ValidationRule(
                name="system_commands",
                description="Detects system command execution",
                pattern=r'(;\s*(rm|del|format|shutdown)|`[^`]*`|\$\([^)]*\))',
                severity="critical",
                action="block"
            ),
            ValidationRule(
                name="network_commands",
                description="Detects network-related commands",
                pattern=r'\b(wget|curl|nc|netcat|telnet|ssh)\s+',
                severity="high",
                action="block"
            ),
            
            # Path Traversal Prevention
            ValidationRule(
                name="path_traversal",
                description="Detects path traversal attempts",
                pattern=r'\.\.[\\/].*\.\.[\\/]',
                severity="high",
                action="block"
            ),
            ValidationRule(
                name="sensitive_files",
                description="Detects access to sensitive system files",
                pattern=r'(\/etc\/passwd|\/etc\/shadow|C:\\Windows\\System32)',
                severity="critical",
                action="block"
            ),
            
            # Information Disclosure Prevention
            ValidationRule(
                name="api_keys",
                description="Detects API key patterns",
                pattern=r'(sk-[A-Za-z0-9]{48}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z\\-_]{35})',
                severity="critical",
                action="block"
            ),
            ValidationRule(
                name="credentials",
                description="Detects credential patterns",
                pattern=r'(password\s*[:=]\s*[^\s]+|api[_\s]?key\s*[:=]\s*[^\s]+)',
                severity="high",
                action="sanitize"
            ),
            ValidationRule(
                name="pii_ssn",
                description="Detects Social Security Numbers",
                pattern=r'\b\d{3}-\d{2}-\d{4}\b',
                severity="high",
                action="sanitize"
            ),
            ValidationRule(
                name="pii_credit_card",
                description="Detects credit card numbers",
                pattern=r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
                severity="high",
                action="sanitize"
            )
        ]
        
        # Filter rules based on validation level
        if self.validation_level == ValidationLevel.PERMISSIVE:
            rules = [r for r in rules if r.severity == "critical"]
        elif self.validation_level == ValidationLevel.STRICT:
            # All rules enabled for strict mode
            pass
        
        return rules
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> ValidationReport:
        """Validate content against security rules"""
        
        start_time = time.time()
        
        report = ValidationReport(
            content=content,
            overall_result=ValidationResult.PASS
        )
        
        for rule in self.security_rules:
            if not rule.enabled:
                continue
            
            # Apply custom validator if available
            if rule.custom_validator:
                result = rule.custom_validator(content, context)
                if not result:
                    self.handle_rule_failure(rule, report)
                    continue
            
            # Apply pattern-based validation
            matches = re.finditer(rule.pattern, content, re.IGNORECASE | re.MULTILINE)
            
            if any(matches):
                self.handle_rule_failure(rule, report)
            else:
                report.passed_rules.append(rule.name)
        
        # Calculate security score
        total_rules = len(self.security_rules)
        passed_rules = len(report.passed_rules)
        report.security_score = (passed_rules / total_rules) * 100 if total_rules > 0 else 100
        
        # Determine overall result
        if report.failed_rules:
            critical_failures = [r for r in self.security_rules 
                               if r.name in report.failed_rules and r.severity == "critical"]
            if critical_failures:
                report.overall_result = ValidationResult.FAIL
            else:
                report.overall_result = ValidationResult.WARNING
        
        # Generate recommendations
        report.recommendations = self.generate_security_recommendations(report)
        
        report.processing_time = time.time() - start_time
        
        return report
    
    def handle_rule_failure(self, rule: ValidationRule, report: ValidationReport):
        """Handle rule failure based on action"""
        
        if rule.action == "block":
            report.failed_rules.append(rule.name)
        elif rule.action == "warn":
            report.warnings.append(f"{rule.name}: {rule.description}")
        elif rule.action == "sanitize":
            report.warnings.append(f"{rule.name}: Content requires sanitization")
    
    def generate_security_recommendations(self, report: ValidationReport) -> List[str]:
        """Generate security recommendations based on validation results"""
        
        recommendations = []
        
        if report.failed_rules:
            recommendations.append("Content contains security threats and should be blocked or sanitized")
        
        if report.security_score < 80:
            recommendations.append("Implement additional security controls for content validation")
        
        # Specific recommendations based on failed rules
        failed_rule_names = set(report.failed_rules)
        
        if any('xss' in name or 'script' in name for name in failed_rule_names):
            recommendations.extend([
                "Implement Content Security Policy (CSP)",
                "Use proper HTML encoding for output",
                "Validate and sanitize HTML content"
            ])
        
        if any('sql' in name for name in failed_rule_names):
            recommendations.extend([
                "Use parameterized queries",
                "Implement input validation for database operations",
                "Apply principle of least privilege"
            ])
        
        if any('command' in name for name in failed_rule_names):
            recommendations.extend([
                "Avoid system command execution",
                "Use safe APIs instead of shell commands",
                "Implement command injection prevention"
            ])
        
        return recommendations

class ContentQualityValidator(BaseValidator):
    """Validator for content quality and appropriateness"""
    
    def __init__(self):
        super().__init__("ContentQualityValidator")
        self.quality_rules = self.load_quality_rules()
    
    def load_quality_rules(self) -> List[ValidationRule]:
        """Load content quality rules"""
        
        return [
            ValidationRule(
                name="profanity_check",
                description="Checks for profane language",
                pattern=r'\b(damn|hell|crap|stupid|idiot)\b',  # Basic example
                severity="low",
                action="warn"
            ),
            ValidationRule(
                name="spam_detection",
                description="Detects spam-like content",
                pattern=r'(click here|buy now|limited time|act now).*(!!!|www\.|http)',
                severity="medium",
                action="warn"
            ),
            ValidationRule(
                name="excessive_caps",
                description="Detects excessive use of capital letters",
                pattern=r'\b[A-Z]{5,}\b.*\b[A-Z]{5,}\b',
                severity="low",
                action="warn"
            ),
            ValidationRule(
                name="repetitive_content",
                description="Detects repetitive content patterns",
                pattern=r'(.{10,})\1{3,}',  # Same content repeated 3+ times
                severity="medium",
                action="warn"
            )
        ]
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> ValidationReport:
        """Validate content quality"""
        
        start_time = time.time()
        
        report = ValidationReport(
            content=content,
            overall_result=ValidationResult.PASS
        )
        
        for rule in self.quality_rules:
            if not rule.enabled:
                continue
            
            matches = list(re.finditer(rule.pattern, content, re.IGNORECASE | re.MULTILINE))
            
            if matches:
                if rule.action == "warn":
                    report.warnings.append(f"{rule.name}: {rule.description}")
                else:
                    report.failed_rules.append(rule.name)
            else:
                report.passed_rules.append(rule.name)
        
        # Calculate quality score
        total_rules = len(self.quality_rules)
        passed_rules = len(report.passed_rules)
        quality_score = (passed_rules / total_rules) * 100 if total_rules > 0 else 100
        
        # Adjust overall result based on quality issues
        if len(report.warnings) > 2:
            report.overall_result = ValidationResult.WARNING
        
        report.processing_time = time.time() - start_time
        
        return report

class ComplianceValidator(BaseValidator):
    """Validator for regulatory compliance (GDPR, HIPAA, etc.)"""
    
    def __init__(self, compliance_standards: List[str] = None):
        super().__init__("ComplianceValidator")
        self.compliance_standards = compliance_standards or ["GDPR", "HIPAA"]
        self.compliance_rules = self.load_compliance_rules()
    
    def load_compliance_rules(self) -> List[ValidationRule]:
        """Load compliance validation rules"""
        
        rules = []
        
        if "GDPR" in self.compliance_standards:
            rules.extend([
                ValidationRule(
                    name="gdpr_personal_data",
                    description="Detects personal data that may violate GDPR",
                    pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    severity="high",
                    action="sanitize"
                ),
                ValidationRule(
                    name="gdpr_phone_numbers",
                    description="Detects phone numbers",
                    pattern=r'\b\+?[\d\s\-\(\)]{10,}\b',
                    severity="medium",
                    action="warn"
                )
            ])
        
        if "HIPAA" in self.compliance_standards:
            rules.extend([
                ValidationRule(
                    name="hipaa_medical_records",
                    description="Detects medical record numbers",
                    pattern=r'\b(MRN|Medical Record|Patient ID)[:\s#]*\d+\b',
                    severity="critical",
                    action="block"
                ),
                ValidationRule(
                    name="hipaa_health_info",
                    description="Detects health information",
                    pattern=r'\b(diagnosis|prescription|treatment|medical condition|patient)\b',
                    severity="medium",
                    action="warn"
                )
            ])
        
        return rules
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> ValidationReport:
        """Validate compliance requirements"""
        
        start_time = time.time()
        
        report = ValidationReport(
            content=content,
            overall_result=ValidationResult.PASS
        )
        
        for rule in self.compliance_rules:
            if not rule.enabled:
                continue
            
            matches = list(re.finditer(rule.pattern, content, re.IGNORECASE | re.MULTILINE))
            
            if matches:
                if rule.action == "block":
                    report.failed_rules.append(rule.name)
                elif rule.action == "warn":
                    report.warnings.append(f"{rule.name}: {rule.description}")
            else:
                report.passed_rules.append(rule.name)
        
        # Determine compliance result
        if report.failed_rules:
            report.overall_result = ValidationResult.FAIL
        elif report.warnings:
            report.overall_result = ValidationResult.WARNING
        
        report.processing_time = time.time() - start_time
        
        return report

class OutputValidationFramework:
    """Main framework for comprehensive output validation"""
    
    def __init__(self, validation_level: ValidationLevel = ValidationLevel.MODERATE):
        self.validation_level = validation_level
        self.validators = []
        self.validation_history = []
        self.setup_default_validators()
    
    def setup_default_validators(self):
        """Setup default validators"""
        
        self.validators = [
            SecurityValidator(self.validation_level),
            ContentQualityValidator(),
            ComplianceValidator()
        ]
    
    def add_validator(self, validator: BaseValidator):
        """Add custom validator"""
        self.validators.append(validator)
    
    def remove_validator(self, validator_name: str):
        """Remove validator by name"""
        self.validators = [v for v in self.validators if v.name != validator_name]
    
    def validate_output(self, content: str, context: Dict[str, Any] = None) -> Dict[str, ValidationReport]:
        """Validate output using all enabled validators"""
        
        results = {}
        
        for validator in self.validators:
            if validator.enabled:
                try:
                    result = validator.validate(content, context)
                    results[validator.name] = result
                except Exception as e:
                    logging.error(f"Validator {validator.name} failed: {e}")
                    # Create error report
                    error_report = ValidationReport(
                        content=content,
                        overall_result=ValidationResult.FAIL,
                        failed_rules=[f"validator_error_{validator.name}"],
                        recommendations=[f"Fix validator {validator.name}: {e}"]
                    )
                    results[validator.name] = error_report
        
        # Store in history
        self.validation_history.append({
            'timestamp': time.time(),
            'content_hash': hashlib.md5(content.encode()).hexdigest(),
            'results': results
        })
        
        return results
    
    def get_overall_assessment(self, validation_results: Dict[str, ValidationReport]) -> Dict[str, Any]:
        """Get overall assessment from all validation results"""
        
        overall_result = ValidationResult.PASS
        all_recommendations = []
        total_score = 0.0
        critical_issues = []
        
        for validator_name, report in validation_results.items():
            # Collect recommendations
            all_recommendations.extend(report.recommendations)
            
            # Calculate weighted score
            if hasattr(report, 'security_score'):
                total_score += report.security_score
            else:
                # Default scoring for non-security validators
                passed = len(report.passed_rules)
                total = passed + len(report.failed_rules)
                score = (passed / total * 100) if total > 0 else 100
                total_score += score
            
            # Check for critical issues
            if report.overall_result == ValidationResult.FAIL:
                overall_result = ValidationResult.FAIL
                critical_issues.append(validator_name)
            elif report.overall_result == ValidationResult.WARNING and overall_result == ValidationResult.PASS:
                overall_result = ValidationResult.WARNING
        
        # Calculate average score
        avg_score = total_score / len(validation_results) if validation_results else 0
        
        return {
            'overall_result': overall_result,
            'average_score': avg_score,
            'critical_issues': critical_issues,
            'recommendations': list(set(all_recommendations)),  # Remove duplicates
            'validator_count': len(validation_results),
            'assessment_summary': self.generate_assessment_summary(overall_result, avg_score, critical_issues)
        }
    
    def generate_assessment_summary(self, result: ValidationResult, score: float, critical_issues: List[str]) -> str:
        """Generate human-readable assessment summary"""
        
        if result == ValidationResult.FAIL:
            return f"FAILED validation with {len(critical_issues)} critical issues. Content should be blocked."
        elif result == ValidationResult.WARNING:
            return f"PASSED with warnings. Score: {score:.1f}%. Review recommended."
        else:
            return f"PASSED all validations. Score: {score:.1f}%. Content is safe to use."
    
    def generate_comprehensive_report(self, content: str, validation_results: Dict[str, ValidationReport]) -> str:
        """Generate comprehensive validation report"""
        
        overall_assessment = self.get_overall_assessment(validation_results)
        
        report = []
        report.append("=" * 70)
        report.append("COMPREHENSIVE OUTPUT VALIDATION REPORT")
        report.append("=" * 70)
        report.append(f"Validation Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Content Length: {len(content)} characters")
        report.append(f"Content Hash: {hashlib.md5(content.encode()).hexdigest()}")
        report.append("")
        
        # Overall assessment
        report.append("OVERALL ASSESSMENT:")
        report.append("-" * 20)
        report.append(f"Result: {overall_assessment['overall_result'].value.upper()}")
        report.append(f"Average Score: {overall_assessment['average_score']:.1f}%")
        report.append(f"Summary: {overall_assessment['assessment_summary']}")
        report.append("")
        
        # Individual validator results
        report.append("VALIDATOR RESULTS:")
        report.append("-" * 20)
        
        for validator_name, result in validation_results.items():
            report.append(f"\n{validator_name}:")
            report.append(f"  Result: {result.overall_result.value.upper()}")
            if hasattr(result, 'security_score'):
                report.append(f"  Score: {result.security_score:.1f}%")
            report.append(f"  Processing Time: {result.processing_time:.3f}s")
            
            if result.failed_rules:
                report.append(f"  Failed Rules: {', '.join(result.failed_rules)}")
            
            if result.warnings:
                report.append(f"  Warnings: {len(result.warnings)}")
                for warning in result.warnings[:3]:  # Show first 3 warnings
                    report.append(f"    - {warning}")
        
        # Recommendations
        if overall_assessment['recommendations']:
            report.append("\nRECOMMENDATIONS:")
            report.append("-" * 15)
            for i, rec in enumerate(overall_assessment['recommendations'][:5], 1):
                report.append(f"{i}. {rec}")
        
        return "\n".join(report)
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validation statistics from history"""
        
        if not self.validation_history:
            return {'total_validations': 0}
        
        total_validations = len(self.validation_history)
        
        # Count results by type
        result_counts = {result.value: 0 for result in ValidationResult}
        
        for entry in self.validation_history:
            for validator_name, report in entry['results'].items():
                result_counts[report.overall_result.value] += 1
        
        return {
            'total_validations': total_validations,
            'result_distribution': result_counts,
            'average_processing_time': sum(
                sum(report.processing_time for report in entry['results'].values())
                for entry in self.validation_history
            ) / total_validations,
            'most_recent_validation': max(entry['timestamp'] for entry in self.validation_history)
        }

def main():
    """Main function to demonstrate output validation framework"""
    
    print("Output Validation Framework Demo")
    print("=" * 35)
    
    # Initialize framework
    framework = OutputValidationFramework(ValidationLevel.MODERATE)
    
    # Test cases
    test_cases = [
        "This is normal, safe content.",
        "Click here: <script>alert('XSS')</script>",
        "SQL: SELECT * FROM users WHERE id = '1' OR '1'='1'",
        "Command: ls -la; rm -rf /",
        "API Key: sk-1234567890abcdef1234567890abcdef12345678",
        "Email: john.doe@example.com, Phone: +1-555-123-4567",
        "Patient ID: 12345, Diagnosis: diabetes",
    ]
    
    for i, content in enumerate(test_cases, 1):
        print(f"\nTest {i}: {content[:50]}...")
        
        # Validate content
        results = framework.validate_output(content)
        
        # Get overall assessment
        assessment = framework.get_overall_assessment(results)
        
        print(f"Result: {assessment['overall_result'].value.upper()}")
        print(f"Score: {assessment['average_score']:.1f}%")
        
        if assessment['critical_issues']:
            print(f"Critical Issues: {', '.join(assessment['critical_issues'])}")
        
        if assessment['recommendations']:
            print(f"Recommendation: {assessment['recommendations'][0]}")
    
    # Show statistics
    stats = framework.get_validation_statistics()
    print(f"\nValidation Statistics:")
    print(f"Total Validations: {stats['total_validations']}")
    print(f"Average Processing Time: {stats['average_processing_time']:.3f}s")

if __name__ == "__main__":
    main()