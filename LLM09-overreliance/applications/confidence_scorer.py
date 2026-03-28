#!/usr/bin/env python3
"""
LLM Output Confidence Scorer
"""

import re
from typing import Dict, Any, List

class ConfidenceScorer:
    def __init__(self):
        self.uncertainty_indicators = self.load_indicators()
    
    def load_indicators(self) -> Dict[str, List[str]]:
        return {
            'high_uncertainty': [
                'i think', 'maybe', 'possibly', 'might be', 'could be',
                'not sure', 'uncertain', 'unclear', 'probably'
            ],
            'medium_uncertainty': [
                'likely', 'seems', 'appears', 'suggests', 'indicates'
            ],
            'hedging': [
                'in my opinion', 'i believe', 'it seems that', 'generally'
            ]
        }
    
    def score_output(self, llm_output: str, context: str = "") -> Dict[str, Any]:
        """Score confidence level of LLM output"""
        
        output_lower = llm_output.lower()
        
        # Count uncertainty indicators
        uncertainty_count = 0
        found_indicators = []
        
        for category, indicators in self.uncertainty_indicators.items():
            for indicator in indicators:
                if indicator in output_lower:
                    uncertainty_count += 1
                    found_indicators.append({
                        'indicator': indicator,
                        'category': category
                    })
        
        # Check for factual claims without sources
        has_factual_claims = self.detect_factual_claims(llm_output)
        has_sources = self.detect_sources(llm_output)
        
        # Calculate confidence score
        base_confidence = 0.7
        
        # Reduce confidence for uncertainty
        confidence = base_confidence - (uncertainty_count * 0.1)
        
        # Reduce confidence for unsourced factual claims
        if has_factual_claims and not has_sources:
            confidence -= 0.2
        
        # Ensure score is between 0 and 1
        confidence = max(0.0, min(1.0, confidence))
        
        return {
            'confidence_score': confidence,
            'confidence_level': self.get_confidence_level(confidence),
            'uncertainty_indicators': found_indicators,
            'has_factual_claims': has_factual_claims,
            'has_sources': has_sources,
            'recommendation': self.generate_recommendation(confidence, has_factual_claims, has_sources)
        }
    
    def detect_factual_claims(self, text: str) -> bool:
        """Detect if text contains factual claims"""
        
        factual_patterns = [
            r'\d+%',  # Percentages
            r'in \d{4}',  # Years
            r'according to',  # Claims
            r'studies show',
            r'research indicates'
        ]
        
        for pattern in factual_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def detect_sources(self, text: str) -> bool:
        """Detect if text cites sources"""
        
        source_patterns = [
            r'source:',
            r'reference:',
            r'\[citation\]',
            r'http[s]?://',
            r'doi:'
        ]
        
        for pattern in source_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def get_confidence_level(self, score: float) -> str:
        """Convert score to confidence level"""
        if score >= 0.8:
            return 'high'
        elif score >= 0.6:
            return 'medium'
        elif score >= 0.4:
            return 'low'
        else:
            return 'very_low'
    
    def generate_recommendation(self, confidence: float, has_claims: bool, has_sources: bool) -> str:
        """Generate usage recommendation"""
        
        if confidence < 0.4:
            return "VERIFY: Low confidence - verify all information before use"
        elif has_claims and not has_sources:
            return "CAUTION: Factual claims without sources - verify independently"
        elif confidence < 0.6:
            return "REVIEW: Medium confidence - review before relying on output"
        else:
            return "ACCEPTABLE: Output appears reliable but always verify critical information"

def main():
    print("Confidence Scorer")
    print("=" * 18)
    
    scorer = ConfidenceScorer()
    
    # Test outputs
    test_outputs = [
        "Python was created in 1991 by Guido van Rossum.",
        "I think Python might have been created around 1990, but I'm not sure.",
        "Studies show that 85% of developers prefer Python, according to research."
    ]
    
    for i, output in enumerate(test_outputs, 1):
        print(f"\nTest {i}: {output[:50]}...")
        result = scorer.score_output(output)
        print(f"Confidence: {result['confidence_score']:.2f} ({result['confidence_level']})")
        print(f"Recommendation: {result['recommendation']}")

if __name__ == "__main__":
    main()
