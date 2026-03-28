#!/usr/bin/env python3
"""
Permission and Agency Analyzer
"""

from typing import List, Dict, Any, Set

class PermissionAnalyzer:
    def __init__(self):
        self.permission_levels = {
            'read': 1,
            'write': 2,
            'execute': 3,
            'admin': 4,
            'root': 5
        }
    
    def analyze_permissions(self, agent_config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze agent permissions for excessive agency"""
        
        issues = []
        
        # Check granted permissions
        permissions = agent_config.get('permissions', [])
        actions = agent_config.get('allowed_actions', [])
        oversight = agent_config.get('human_oversight', False)
        
        # Check for excessive permissions
        if 'admin' in permissions or 'root' in permissions:
            issues.append({
                'type': 'excessive_permissions',
                'severity': 'critical',
                'description': 'Agent has admin/root permissions'
            })
        
        # Check for dangerous actions without oversight
        dangerous_actions = ['delete', 'modify', 'execute', 'transfer']
        has_dangerous = any(action in actions for action in dangerous_actions)
        
        if has_dangerous and not oversight:
            issues.append({
                'type': 'no_oversight',
                'severity': 'high',
                'description': 'Dangerous actions without human oversight'
            })
        
        # Check for unrestricted scope
        if agent_config.get('scope') == 'unrestricted':
            issues.append({
                'type': 'unrestricted_scope',
                'severity': 'high',
                'description': 'Agent has unrestricted operational scope'
            })
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(permissions, actions, oversight)
        
        return {
            'agent_id': agent_config.get('id', 'unknown'),
            'issues': issues,
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(risk_score),
            'recommendations': self.generate_recommendations(issues)
        }
    
    def calculate_risk_score(self, permissions: List[str], actions: List[str], oversight: bool) -> float:
        """Calculate overall risk score"""
        
        score = 0.0
        
        # Permission risk
        for perm in permissions:
            score += self.permission_levels.get(perm, 0) * 10
        
        # Action risk
        score += len(actions) * 5
        
        # Oversight mitigation
        if not oversight:
            score *= 1.5
        
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
    
    def generate_recommendations(self, issues: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        
        recommendations = []
        
        for issue in issues:
            if issue['type'] == 'excessive_permissions':
                recommendations.append("Reduce permissions to minimum required")
            elif issue['type'] == 'no_oversight':
                recommendations.append("Implement human-in-the-loop for critical actions")
            elif issue['type'] == 'unrestricted_scope':
                recommendations.append("Define clear operational boundaries")
        
        if not recommendations:
            recommendations.append("Permission configuration appears appropriate")
        
        return recommendations

def main():
    print("Permission Analyzer")
    print("=" * 20)
    
    analyzer = PermissionAnalyzer()
    
    # Test configuration
    test_config = {
        'id': 'agent_001',
        'permissions': ['read', 'write', 'execute'],
        'allowed_actions': ['delete', 'modify', 'transfer'],
        'human_oversight': False,
        'scope': 'unrestricted'
    }
    
    result = analyzer.analyze_permissions(test_config)
    
    print(f"Agent: {result['agent_id']}")
    print(f"Risk Score: {result['risk_score']:.1f}/100")
    print(f"Risk Level: {result['risk_level'].upper()}")
    print(f"\nIssues: {len(result['issues'])}")
    
    for issue in result['issues']:
        print(f"  - [{issue['severity']}] {issue['description']}")
    
    print(f"\nRecommendations:")
    for rec in result['recommendations']:
        print(f"  - {rec}")

if __name__ == "__main__":
    main()
