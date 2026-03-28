#!/usr/bin/env python3
"""
Model Extraction Attack Detector
"""

import time
from collections import defaultdict
from typing import Dict, Any, List

class ModelExtractionDetector:
    def __init__(self):
        self.user_queries = defaultdict(list)
        self.suspicious_patterns = self.load_patterns()
    
    def load_patterns(self) -> Dict[str, Any]:
        return {
            'high_frequency': {
                'threshold': 100,  # queries per hour
                'severity': 'high'
            },
            'systematic_probing': {
                'threshold': 0.8,  # similarity threshold
                'severity': 'critical'
            },
            'edge_case_testing': {
                'patterns': ['test', 'probe', 'check', 'verify'],
                'severity': 'medium'
            }
        }
    
    def analyze_query(self, user_id: str, query: str, response: str) -> Dict[str, Any]:
        """Analyze query for model extraction indicators"""
        
        current_time = time.time()
        
        # Record query
        self.user_queries[user_id].append({
            'query': query,
            'response': response,
            'timestamp': current_time
        })
        
        # Clean old queries (keep last hour)
        self.user_queries[user_id] = [
            q for q in self.user_queries[user_id]
            if current_time - q['timestamp'] < 3600
        ]
        
        indicators = []
        
        # Check query frequency
        query_count = len(self.user_queries[user_id])
        if query_count > self.suspicious_patterns['high_frequency']['threshold']:
            indicators.append({
                'type': 'high_frequency',
                'severity': 'high',
                'description': f'{query_count} queries in last hour'
            })
        
        # Check for systematic probing
        if self.detect_systematic_probing(user_id):
            indicators.append({
                'type': 'systematic_probing',
                'severity': 'critical',
                'description': 'Systematic query patterns detected'
            })
        
        # Check for edge case testing
        if self.detect_edge_case_testing(query):
            indicators.append({
                'type': 'edge_case_testing',
                'severity': 'medium',
                'description': 'Edge case testing detected'
            })
        
        risk_score = self.calculate_risk_score(indicators)
        
        return {
            'user_id': user_id,
            'indicators': indicators,
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(risk_score),
            'action': self.determine_action(risk_score)
        }
    
    def detect_systematic_probing(self, user_id: str) -> bool:
        """Detect systematic probing patterns"""
        
        queries = self.user_queries[user_id]
        
        if len(queries) < 10:
            return False
        
        # Check for similar query patterns
        recent_queries = [q['query'] for q in queries[-10:]]
        
        # Simple similarity check (can be improved)
        similar_count = 0
        for i in range(len(recent_queries) - 1):
            if self.calculate_similarity(recent_queries[i], recent_queries[i+1]) > 0.8:
                similar_count += 1
        
        return similar_count > 5
    
    def detect_edge_case_testing(self, query: str) -> bool:
        """Detect edge case testing"""
        
        query_lower = query.lower()
        
        for pattern in self.suspicious_patterns['edge_case_testing']['patterns']:
            if pattern in query_lower:
                return True
        
        return False
    
    def calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate simple similarity score"""
        
        words1 = set(s1.lower().split())
        words2 = set(s2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union)
    
    def calculate_risk_score(self, indicators: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score"""
        
        severity_weights = {
            'critical': 40,
            'high': 25,
            'medium': 15,
            'low': 5
        }
        
        score = sum(severity_weights.get(ind['severity'], 0) for ind in indicators)
        
        return min(score, 100)
    
    def get_risk_level(self, score: float) -> str:
        """Get risk level from score"""
        if score >= 70:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 30:
            return 'medium'
        else:
            return 'low'
    
    def determine_action(self, risk_score: float) -> str:
        """Determine recommended action"""
        if risk_score >= 70:
            return 'BLOCK: Potential model extraction attack'
        elif risk_score >= 50:
            return 'THROTTLE: Suspicious activity detected'
        elif risk_score >= 30:
            return 'MONITOR: Elevated risk level'
        else:
            return 'ALLOW: Normal usage'

def main():
    print("Model Extraction Detector")
    print("=" * 27)
    
    detector = ModelExtractionDetector()
    
    # Simulate suspicious queries
    for i in range(120):
        result = detector.analyze_query(
            "user123",
            f"Test query {i} with similar pattern",
            f"Response {i}"
        )
        
        if result['indicators']:
            print(f"\nQuery {i}:")
            print(f"Risk Score: {result['risk_score']:.1f}")
            print(f"Risk Level: {result['risk_level'].upper()}")
            print(f"Action: {result['action']}")
            break

if __name__ == "__main__":
    main()
