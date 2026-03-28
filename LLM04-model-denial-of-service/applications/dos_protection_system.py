#!/usr/bin/env python3
"""
DoS Protection System for LLM Applications
"""

import time
import hashlib
from collections import defaultdict
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class RateLimitConfig:
    requests_per_minute: int = 60
    tokens_per_hour: int = 100000
    max_input_length: int = 4000
    max_output_tokens: int = 2000
    concurrent_requests: int = 5

class DoSProtectionSystem:
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        self.user_requests = defaultdict(list)
        self.user_tokens = defaultdict(list)
        self.blocked_users = {}
    
    def check_request(self, user_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check if request should be allowed"""
        
        current_time = time.time()
        
        # Check if user is blocked
        if user_id in self.blocked_users:
            if current_time < self.blocked_users[user_id]:
                return {'allowed': False, 'reason': 'User temporarily blocked'}
            else:
                del self.blocked_users[user_id]
        
        # Clean old data
        self.cleanup_old_data(user_id, current_time)
        
        # Check rate limits
        if not self.check_rate_limit(user_id, current_time):
            self.blocked_users[user_id] = current_time + 300  # Block for 5 minutes
            return {'allowed': False, 'reason': 'Rate limit exceeded'}
        
        # Check input length
        input_text = request_data.get('prompt', '')
        if len(input_text) > self.config.max_input_length:
            return {'allowed': False, 'reason': 'Input too long'}
        
        # Check for resource-intensive patterns
        if self.is_resource_intensive(input_text):
            return {'allowed': False, 'reason': 'Resource-intensive request detected'}
        
        # Record request
        self.user_requests[user_id].append(current_time)
        
        return {'allowed': True, 'reason': 'Request approved'}
    
    def check_rate_limit(self, user_id: str, current_time: float) -> bool:
        """Check if user is within rate limits"""
        
        recent_requests = [t for t in self.user_requests[user_id] if current_time - t < 60]
        
        if len(recent_requests) >= self.config.requests_per_minute:
            return False
        
        return True
    
    def is_resource_intensive(self, text: str) -> bool:
        """Detect resource-intensive request patterns"""
        
        import re
        
        intensive_patterns = [
            r'repeat.{0,20}\d{3,}',  # repeat X times
            r'generate.{0,20}\d{4,}',  # generate large amounts
            r'calculate.{0,20}\d{4,}',  # complex calculations
        ]
        
        for pattern in intensive_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def cleanup_old_data(self, user_id: str, current_time: float):
        """Remove old request data"""
        
        self.user_requests[user_id] = [
            t for t in self.user_requests[user_id] 
            if current_time - t < 3600
        ]

def main():
    print("DoS Protection System")
    print("=" * 20)
    
    protection = DoSProtectionSystem()
    
    # Test requests
    for i in range(70):
        result = protection.check_request("user123", {"prompt": f"Test request {i}"})
        if not result['allowed']:
            print(f"Request {i}: BLOCKED - {result['reason']}")
            break
        print(f"Request {i}: ALLOWED")
        time.sleep(0.01)

if __name__ == "__main__":
    main()
