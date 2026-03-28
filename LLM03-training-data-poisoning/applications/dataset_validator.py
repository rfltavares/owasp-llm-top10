#!/usr/bin/env python3
"""
Dataset Validator
Comprehensive validation system for training datasets
"""

import re
import json
import hashlib
import numpy as np
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import Counter

@dataclass
class ValidationResult:
    is_valid: bool
    validation_score: float
    issues: List[Dict[str, Any]]
    warnings: List[str]
    statistics: Dict[str, Any]
    recommendations: List[str]

class DatasetValidator:
    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode
        self.validation_rules = self.load_validation_rules()
    
    def load_validation_rules(self) -> Dict[str, Any]:
        """Load comprehensive validation rules"""
        return {
            'required_fields': ['input', 'output'],
            'optional_fields': ['label', 'metadata', 'source', 'timestamp'],
            'max_input_length': 10000,
            'max_output_length': 5000,
            'min_dataset_size': 100,
            'max_duplicate_rate': 0.1,
            'min_label_diversity': 2,
            'max_label_imbalance': 0.9,
            'forbidden_patterns': [
                r'<script[^>]*>',
                r'eval\s*\(',
                r'exec\s*\(',
                r'__import__',
                r'rm\s+-rf',
                r'DROP\s+TABLE'
            ]
        }
    
    def validate_dataset(self, dataset: List[Dict[str, Any]]) -> ValidationResult:
        """Comprehensive dataset validation"""
        
        issues = []
        warnings = []
        
        print(f"Validating dataset with {len(dataset)} samples...")
        
        # Basic structure validation
        structure_issues = self.validate_structure(dataset)
        issues.extend(structure_issues)
        
        # Content validation
        content_issues = self.validate_content(dataset)
        issues.extend(content_issues)
        
        # Statistical validation
        stats_issues, statistics = self.validate_statistics(dataset)
        issues.extend(stats_issues)
        
        # Quality validation
        quality_issues = self.validate_quality(dataset)
        issues.extend(quality_issues)
        
        # Security validation
        security_issues = self.validate_security(dataset)
        issues.extend(security_issues)
        
        # Calculate validation score
        validation_score = self.calculate_validation_score(issues, len(dataset))
        
        # Determine if valid
        critical_issues = [i for i in issues if i['severity'] == 'critical']
        is_valid = len(critical_issues) == 0 and validation_score >= 0.7
        
        # Generate recommendations
        recommendations = self.generate_recommendations(issues, statistics)
        
        return ValidationResult(
            is_valid=is_valid,
            validation_score=validation_score,
            issues=issues,
            warnings=warnings,
            statistics=statistics,
            recommendations=recommendations
        )
    
    def validate_structure(self, dataset: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate dataset structure"""
        issues = []
        
        # Check minimum size
        if len(dataset) < self.validation_rules['min_dataset_size']:
            issues.append({
                'type': 'insufficient_size',
                'severity': 'high',
                'message': f"Dataset has only {len(dataset)} samples, minimum is {self.validation_rules['min_dataset_size']}",
                'affected_samples': []
            })
        
        # Check required fields
        for idx, sample in enumerate(dataset):
            missing_fields = [f for f in self.validation_rules['required_fields'] if f not in sample]
            if missing_fields:
                issues.append({
                    'type': 'missing_fields',
                    'severity': 'critical',
                    'message': f"Sample {idx} missing required fields: {missing_fields}",
                    'affected_samples': [idx]
                })
        
        return issues
    
    def validate_content(self, dataset: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate content of samples"""
        issues = []
        
        for idx, sample in enumerate(dataset):
            # Check input length
            if 'input' in sample:
                input_len = len(str(sample['input']))
                if input_len > self.validation_rules['max_input_length']:
                    issues.append({
                        'type': 'input_too_long',
                        'severity': 'medium',
                        'message': f"Sample {idx} input length {input_len} exceeds maximum",
                        'affected_samples': [idx]
                    })
                elif input_len == 0:
                    issues.append({
                        'type': 'empty_input',
                        'severity': 'high',
                        'message': f"Sample {idx} has empty input",
                        'affected_samples': [idx]
                    })
            
            # Check output length
            if 'output' in sample:
                output_len = len(str(sample['output']))
                if output_len > self.validation_rules['max_output_length']:
                    issues.append({
                        'type': 'output_too_long',
                        'severity': 'medium',
                        'message': f"Sample {idx} output length {output_len} exceeds maximum",
                        'affected_samples': [idx]
                    })
                elif output_len == 0:
                    issues.append({
                        'type': 'empty_output',
                        'severity': 'high',
                        'message': f"Sample {idx} has empty output",
                        'affected_samples': [idx]
                    })
        
        return issues
    
    def validate_statistics(self, dataset: List[Dict[str, Any]]) -> tuple:
        """Validate statistical properties"""
        issues = []
        statistics = {}
        
        # Calculate statistics
        statistics['total_samples'] = len(dataset)
        
        # Label distribution
        labels = [s.get('label', 'unknown') for s in dataset]
        label_counts = Counter(labels)
        statistics['label_distribution'] = dict(label_counts)
        statistics['unique_labels'] = len(label_counts)
        
        # Check label diversity
        if statistics['unique_labels'] < self.validation_rules['min_label_diversity']:
            issues.append({
                'type': 'low_label_diversity',
                'severity': 'medium',
                'message': f"Only {statistics['unique_labels']} unique labels found",
                'affected_samples': []
            })
        
        # Check label imbalance
        if label_counts:
            max_label_freq = max(label_counts.values()) / len(dataset)
            if max_label_freq > self.validation_rules['max_label_imbalance']:
                issues.append({
                    'type': 'label_imbalance',
                    'severity': 'high',
                    'message': f"Severe label imbalance: {max_label_freq*100:.1f}% in one class",
                    'affected_samples': []
                })
        
        # Duplicate detection
        content_hashes = {}
        for idx, sample in enumerate(dataset):
            content = str(sample.get('input', '')) + str(sample.get('output', ''))
            content_hash = hashlib.md5(content.encode()).hexdigest()
            if content_hash in content_hashes:
                content_hashes[content_hash].append(idx)
            else:
                content_hashes[content_hash] = [idx]
        
        duplicates = {h: indices for h, indices in content_hashes.items() if len(indices) > 1}
        duplicate_count = sum(len(indices) - 1 for indices in duplicates.values())
        duplicate_rate = duplicate_count / len(dataset)
        
        statistics['duplicate_count'] = duplicate_count
        statistics['duplicate_rate'] = duplicate_rate
        
        if duplicate_rate > self.validation_rules['max_duplicate_rate']:
            issues.append({
                'type': 'high_duplicate_rate',
                'severity': 'high',
                'message': f"Duplicate rate {duplicate_rate*100:.1f}% exceeds threshold",
                'affected_samples': []
            })
        
        return issues, statistics
    
    def validate_quality(self, dataset: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate data quality"""
        issues = []
        
        quality_issues_count = 0
        
        for idx, sample in enumerate(dataset):
            sample_issues = []
            
            # Check for placeholder text
            text = str(sample.get('input', '')) + ' ' + str(sample.get('output', ''))
            placeholders = ['lorem ipsum', 'test test', 'example', 'placeholder', 'TODO', 'FIXME']
            
            for placeholder in placeholders:
                if placeholder.lower() in text.lower():
                    sample_issues.append(f"Contains placeholder: {placeholder}")
            
            # Check for excessive repetition
            words = text.lower().split()
            if len(words) > 10:
                word_counts = Counter(words)
                most_common_word, count = word_counts.most_common(1)[0]
                if count > len(words) * 0.3:  # More than 30% same word
                    sample_issues.append(f"Excessive repetition of '{most_common_word}'")
            
            if sample_issues:
                quality_issues_count += 1
                if quality_issues_count <= 10:  # Report first 10
                    issues.append({
                        'type': 'quality_issue',
                        'severity': 'low',
                        'message': f"Sample {idx}: {', '.join(sample_issues)}",
                        'affected_samples': [idx]
                    })
        
        if quality_issues_count > len(dataset) * 0.1:  # More than 10%
            issues.append({
                'type': 'widespread_quality_issues',
                'severity': 'medium',
                'message': f"{quality_issues_count} samples have quality issues",
                'affected_samples': []
            })
        
        return issues
    
    def validate_security(self, dataset: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate security aspects"""
        issues = []
        
        for idx, sample in enumerate(dataset):
            text = str(sample.get('input', '')) + ' ' + str(sample.get('output', ''))
            
            # Check forbidden patterns
            for pattern in self.validation_rules['forbidden_patterns']:
                if re.search(pattern, text, re.IGNORECASE):
                    issues.append({
                        'type': 'forbidden_pattern',
                        'severity': 'critical',
                        'message': f"Sample {idx} contains forbidden pattern: {pattern}",
                        'affected_samples': [idx]
                    })
        
        return issues
    
    def calculate_validation_score(self, issues: List[Dict[str, Any]], dataset_size: int) -> float:
        """Calculate overall validation score"""
        
        if not issues:
            return 1.0
        
        # Weight by severity
        severity_weights = {'critical': 1.0, 'high': 0.5, 'medium': 0.25, 'low': 0.1}
        
        total_penalty = sum(severity_weights.get(issue['severity'], 0.1) for issue in issues)
        max_penalty = dataset_size * 1.0  # Maximum possible penalty
        
        score = max(0.0, 1.0 - (total_penalty / max_penalty))
        
        return score
    
    def generate_recommendations(self, issues: List[Dict[str, Any]], statistics: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        # Group issues by type
        issue_types = Counter(issue['type'] for issue in issues)
        
        if 'missing_fields' in issue_types:
            recommendations.append("Add missing required fields to all samples")
        
        if 'high_duplicate_rate' in issue_types:
            recommendations.append("Remove duplicate samples to improve dataset quality")
        
        if 'label_imbalance' in issue_types:
            recommendations.append("Balance label distribution through sampling or data augmentation")
        
        if 'forbidden_pattern' in issue_types:
            recommendations.append("Remove samples with security-sensitive patterns")
        
        if 'quality_issue' in issue_types or 'widespread_quality_issues' in issue_types:
            recommendations.append("Review and improve data quality, remove placeholder text")
        
        if not recommendations:
            recommendations.append("Dataset validation passed - ready for training")
        
        return recommendations

def main():
    """Main function"""
    
    print("Dataset Validator")
    print("=" * 20)
    
    # Example dataset
    example_dataset = [
        {"input": "What is AI?", "output": "Artificial Intelligence", "label": "definition"},
        {"input": "Explain ML", "output": "Machine Learning is...", "label": "definition"},
        {"input": "What is AI?", "output": "Artificial Intelligence", "label": "definition"},  # Duplicate
        {"input": "", "output": "Empty input example", "label": "test"},  # Empty input
        {"input": "Normal question", "output": "Normal answer", "label": "qa"},
    ] * 25  # Repeat to meet minimum size
    
    validator = DatasetValidator()
    result = validator.validate_dataset(example_dataset)
    
    print(f"\nValidation Result: {'PASS' if result.is_valid else 'FAIL'}")
    print(f"Validation Score: {result.validation_score:.2f}")
    print(f"\nIssues Found: {len(result.issues)}")
    
    for issue in result.issues[:5]:
        print(f"  - [{issue['severity'].upper()}] {issue['message']}")
    
    print(f"\nRecommendations:")
    for rec in result.recommendations:
        print(f"  - {rec}")

if __name__ == "__main__":
    main()
