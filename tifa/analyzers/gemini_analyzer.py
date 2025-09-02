"""
Advanced Google Gemini AI Analyzer with intelligent key rotation and beautiful response generation
"""

import google.generativeai as genai
import time
import random
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import re
from ..core.config import Config
from ..core.models import ThreatIntelItem

@dataclass
class APIKeyStats:
    """Track API key usage statistics with token tracking"""
    key: str
    requests_made: int = 0
    tokens_used: int = 0  # Track estimated token usage
    last_request_time: Optional[datetime] = None
    daily_requests: int = 0
    daily_tokens: int = 0  # Track daily token usage
    last_reset_date: Optional[datetime] = None
    is_rate_limited: bool = False
    rate_limit_reset_time: Optional[datetime] = None

@dataclass
class ModelStats:
    """Track model usage and performance"""
    name: str
    requests_made: int = 0
    success_rate: float = 100.0
    avg_response_time: float = 0.0
    last_used: Optional[datetime] = None

class GeminiAIAnalyzer:
    """
    Advanced Gemini AI Analyzer with:
    - Intelligent API key rotation
    - Model fallback system
    - Rate limit handling
    - Beautiful response generation
    - Performance tracking
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.api_keys_stats = [APIKeyStats(key=key) for key in Config.GEMINI_API_KEYS]
        self.model_stats = [ModelStats(name=model["name"]) for model in Config.GEMINI_MODELS]
        self.current_key_index = 0
        self.current_model_index = 0
        self.configure_current_client()
        
    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count for a given text (rough approximation)"""
        # Rough estimation: ~4 characters per token for English text
        return len(text) // 4 + len(text.split()) // 2
    
    def _can_make_request(self, key_stats: APIKeyStats, estimated_tokens: int) -> bool:
        """Check if we can make a request without hitting limits"""
        current_time = datetime.now()
        
        # Reset daily counters if it's a new day
        if (key_stats.last_reset_date is None or 
            current_time.date() > key_stats.last_reset_date.date()):
            key_stats.daily_requests = 0
            key_stats.daily_tokens = 0
            key_stats.last_reset_date = current_time
            key_stats.is_rate_limited = False
        
        # Conservative token limits (using config values)
        daily_token_limit = getattr(Config, 'DAILY_TOKEN_LIMIT', 40000)
        
        # Check if adding this request would exceed limits
        would_exceed_tokens = (key_stats.daily_tokens + estimated_tokens) > daily_token_limit
        would_exceed_requests = key_stats.daily_requests > 40  # Conservative request limit
        
        return not (would_exceed_tokens or would_exceed_requests or key_stats.is_rate_limited)
    
    def configure_current_client(self):
        """Configure Gemini client with current API key"""
        try:
            current_key = self.api_keys_stats[self.current_key_index].key
            genai.configure(api_key=current_key)
            self.logger.info(f"Configured Gemini with API key index: {self.current_key_index}")
        except Exception as e:
            self.logger.error(f"Failed to configure Gemini client: {e}")
    
    def _get_next_available_key(self) -> Tuple[int, APIKeyStats]:
        """Get next available API key with optimized rotation"""
        current_time = datetime.now()
        
        # First, try to find any completely available key
        for i in range(len(self.api_keys_stats)):
            key_index = (self.current_key_index + i) % len(self.api_keys_stats)
            key_stats = self.api_keys_stats[key_index]
            
            # Reset daily counter if it's a new day
            if (key_stats.last_reset_date is None or 
                current_time.date() > key_stats.last_reset_date.date()):
                key_stats.daily_requests = 0
                key_stats.last_reset_date = current_time
                key_stats.is_rate_limited = False  # Reset rate limiting on new day
            
            # Check if rate limit has expired (shorter reset time)
            if (key_stats.is_rate_limited and 
                key_stats.rate_limit_reset_time and 
                current_time > key_stats.rate_limit_reset_time):
                key_stats.is_rate_limited = False
                key_stats.rate_limit_reset_time = None
            
            # Check if key is available
            if not key_stats.is_rate_limited:
                current_model = Config.GEMINI_MODELS[self.current_model_index]
                
                # More lenient RPM check - allow if enough time has passed
                time_since_last = 0
                if key_stats.last_request_time:
                    time_since_last = (current_time - key_stats.last_request_time).total_seconds()
                
                min_interval = 60.0 / current_model["rpm"]  # Minimum seconds between requests
                
                if (key_stats.last_request_time is None or time_since_last >= min_interval * 0.8):  # 80% of interval
                    # Check daily limit with buffer
                    if key_stats.daily_requests < current_model["rpd"] * 0.9:  # Use 90% of daily limit
                        return key_index, key_stats
        
        # If no key is immediately available, use round-robin with the least used key
        least_used_key = min(range(len(self.api_keys_stats)), 
                           key=lambda i: self.api_keys_stats[i].requests_made)
        return least_used_key, self.api_keys_stats[least_used_key]
    
    def _get_next_available_model(self) -> Optional[Dict]:
        """Get next available model with intelligent load balancing"""
        current_time = datetime.now()
        
        # Sort models by priority and recent usage
        model_scores = []
        for i, model in enumerate(Config.GEMINI_MODELS):
            model_stats = self.model_stats[i]
            
            # Calculate score based on success rate, RPM capacity, and recent usage
            success_score = model_stats.success_rate / 100.0
            capacity_score = model["rpm"] / 30.0  # Normalize by max RPM
            
            # Penalize recently used models to distribute load
            usage_penalty = 0
            if model_stats.last_used:
                minutes_since_use = (current_time - model_stats.last_used).total_seconds() / 60
                usage_penalty = max(0, 1 - minutes_since_use / 5)  # Penalty decreases over 5 minutes
            
            total_score = (success_score * 0.5 + capacity_score * 0.3) - (usage_penalty * 0.2)
            model_scores.append((i, total_score, model))
        
        # Sort by score (highest first)
        model_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Return the best available model
        for model_index, score, model in model_scores:
            self.current_model_index = model_index
            return model
        
        # Fallback to first model
        self.current_model_index = 0
        return Config.GEMINI_MODELS[0]
    
    def _make_request(self, prompt: str, max_tokens: int = 500) -> Optional[str]:
        """Make a request to Gemini with intelligent retry logic and token management"""
        
        # Estimate token usage before making request
        estimated_input_tokens = self._estimate_tokens(prompt)
        estimated_total_tokens = estimated_input_tokens + max_tokens
        
        for attempt in range(Config.AI_MAX_RETRIES):
            try:
                # Find a key that can handle this request
                available_key_found = False
                for i in range(len(self.api_keys_stats)):
                    test_key_index = (self.current_key_index + i) % len(self.api_keys_stats)
                    test_key_stats = self.api_keys_stats[test_key_index]
                    
                    if self._can_make_request(test_key_stats, estimated_total_tokens):
                        self.current_key_index = test_key_index
                        available_key_found = True
                        break
                
                if not available_key_found:
                    self.logger.warning(f"🔄 No keys available for {estimated_total_tokens} tokens, attempt {attempt + 1}")
                    if attempt < Config.AI_MAX_RETRIES - 1:
                        time.sleep(2)  # Wait before retrying
                        continue
                    else:
                        return None  # Give up and use fallback
                
                key_stats = self.api_keys_stats[self.current_key_index]
                model_config = self._get_next_available_model()
                if not model_config:
                    self.logger.error("No available models")
                    time.sleep(1)
                    continue
                
                # Configure client and create model
                self.configure_current_client()
                model = genai.GenerativeModel(model_config["name"])
                
                # Configure generation parameters for efficient token usage
                generation_config = {
                    "temperature": 0.2,  # Lower temperature for more focused responses
                    "top_p": 0.6,       # Lower top_p for more deterministic outputs
                    "top_k": 20,        # Reduced top_k for efficiency
                    "max_output_tokens": min(max_tokens, 300),  # Hard limit on tokens
                    "candidate_count": 1,  # Only generate one candidate
                }
                
                # Make the request with optimized safety settings
                start_time = time.time()
                response = model.generate_content(
                    prompt,
                    generation_config=generation_config,
                    safety_settings=[
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    ]
                )
                response_time = time.time() - start_time
                
                # Update statistics with token tracking
                key_stats.requests_made += 1
                key_stats.daily_requests += 1
                key_stats.tokens_used += estimated_total_tokens
                key_stats.daily_tokens += estimated_total_tokens
                key_stats.last_request_time = datetime.now()
                
                model_stats = self.model_stats[self.current_model_index]
                model_stats.requests_made += 1
                model_stats.last_used = datetime.now()
                
                # Update success rate (moving average)
                model_stats.success_rate = (model_stats.success_rate * 0.9) + (100 * 0.1)
                model_stats.avg_response_time = (
                    (model_stats.avg_response_time * (model_stats.requests_made - 1) + response_time) 
                    / model_stats.requests_made
                )
                
                self.logger.info(f"✅ Request successful: Key {self.current_key_index}, Model {model_config['name']}, "
                               f"Tokens: ~{estimated_total_tokens}, Time: {response_time:.2f}s")
                return response.text
                
            except Exception as e:
                error_msg = str(e).lower()
                
                # Handle different types of errors
                if "quota" in error_msg or "rate" in error_msg or "limit" in error_msg:
                    key_stats = self.api_keys_stats[self.current_key_index]
                    key_stats.is_rate_limited = True
                    # Longer rate limit reset time for quota issues (60 seconds)
                    key_stats.rate_limit_reset_time = datetime.now() + timedelta(seconds=60)
                    self.logger.warning(f"⚠️ Rate limited on key {self.current_key_index}, trying next key/model")
                    
                    # Try next key immediately
                    if len(self.api_keys_stats) > 1:
                        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys_stats)
                        self.configure_current_client()
                    
                    # For quota exceeded errors, wait a bit longer
                    if "quota exceeded" in error_msg:
                        time.sleep(2)  # Wait longer for quota resets
                
                elif "model" in error_msg or "not found" in error_msg:
                    model_stats = self.model_stats[self.current_model_index]
                    model_stats.success_rate *= 0.7  # Reduce success rate more aggressively
                    self.logger.warning(f"⚠️ Model error for {model_config['name']}, trying next model")
                    
                    # Try next model
                    self.current_model_index = (self.current_model_index + 1) % len(Config.GEMINI_MODELS)
                
                else:
                    # Generic error - reduce success rate slightly
                    model_stats = self.model_stats[self.current_model_index]
                    model_stats.success_rate *= 0.95
                
                self.logger.error(f"❌ Attempt {attempt + 1} failed: {e}")
                
                # Shorter retry delay
                if attempt < Config.AI_MAX_RETRIES - 1:
                    delay = min(1 + attempt * 0.5, 3)  # Progressive delay: 1s, 1.5s, 2s max
                    time.sleep(delay)
        
        self.logger.error("🚫 All retry attempts failed")
        return None
    
    def generate_threat_summary(self, threat_item: ThreatIntelItem) -> str:
        """Generate efficient threat analysis summary with optimized token usage"""
        
        # Extract key information efficiently
        ioc_count = sum(len(iocs) for iocs in threat_item.iocs.values())
        ioc_types = [ioc_type.replace('_', ' ').title() for ioc_type, iocs in threat_item.iocs.items() if iocs]
        
        # Intelligently preprocess content to minimize tokens
        title_processed = self._preprocess_content(threat_item.title, max_tokens=20)
        summary_processed = self._preprocess_content(threat_item.summary, max_tokens=40)
        
        # Create a very concise, token-efficient prompt
        prompt = f"""Analyze threat:

Title: {title_processed}
Source: {threat_item.source[:20]}
Content: {summary_processed}
IOCs: {ioc_count}

Brief response format:

🎯 TYPE: [Malware/Phishing/Vuln/APT] | SEVERITY: [Critical/High/Medium/Low]

🔍 KEY FINDINGS:
• [Key point 1]
• [Key point 2]

🛡️ ACTIONS:
• [Primary action]

Max 150 words total."""
        
        response = self._make_request(prompt, max_tokens=getattr(Config, 'MAX_SUMMARY_TOKENS', 200))
        
        if response:
            # Clean and format the response
            cleaned_response = self._beautify_response(response)
            return cleaned_response
        else:
            return self._generate_fallback_summary(threat_item)
    
    def _extract_key_content(self, content: str, max_chars: int = 200) -> str:
        """Extract most relevant content from threat description for AI analysis"""
        if not content or len(content) <= max_chars:
            return content
        
        # Priority keywords for cybersecurity content
        priority_keywords = [
            'cve', 'vulnerability', 'exploit', 'malware', 'ransomware', 
            'attack', 'breach', 'zero-day', 'apt', 'phishing', 'trojan',
            'backdoor', 'remote', 'execution', 'privilege', 'escalation'
        ]
        
        sentences = content.split('. ')
        scored_sentences = []
        
        for i, sentence in enumerate(sentences[:10]):  # Only check first 10 sentences
            score = 0
            sentence_lower = sentence.lower()
            
            # Score based on priority keywords
            for keyword in priority_keywords:
                if keyword in sentence_lower:
                    score += 2
            
            # Prefer earlier sentences (usually more important)
            score += (10 - i) * 0.1
            
            # Prefer sentences with technical terms
            if any(term in sentence_lower for term in ['system', 'server', 'network', 'windows', 'linux']):
                score += 1
            
            scored_sentences.append((score, sentence))
        
        # Sort by score and take top sentences until we reach max_chars
        scored_sentences.sort(reverse=True)
        
        result = ""
        for score, sentence in scored_sentences:
            if len(result + sentence + ". ") <= max_chars:
                result += sentence + ". "
            else:
                # Try to fit partial sentence if there's room
                remaining_space = max_chars - len(result) - 3  # -3 for "..."
                if remaining_space > 20:  # Only if meaningful space left
                    result += sentence[:remaining_space] + "..."
                break
        
        return result.strip()
    
    def _preprocess_content(self, content: str, max_tokens: int = 150) -> str:
        """Intelligently preprocess content to fit token limits while preserving meaning"""
        if not content:
            return content
            
        # Quick token estimate
        estimated_tokens = self._estimate_tokens(content)
        if estimated_tokens <= max_tokens:
            return content
        
        # Remove common filler words and phrases to save tokens
        filler_patterns = [
            r'\b(?:the|a|an|and|or|but|in|on|at|to|for|of|with|by)\b',
            r'\s+',  # Multiple spaces
            r'[,;:]\s*',  # Unnecessary punctuation
        ]
        
        processed = content
        for pattern in filler_patterns:
            processed = re.sub(pattern, ' ', processed, flags=re.IGNORECASE)
        
        # Split into sentences and prioritize those with cybersecurity keywords
        sentences = [s.strip() for s in processed.split('.') if s.strip()]
        
        # Score sentences by cybersecurity relevance
        cyber_keywords = [
            'vulnerability', 'exploit', 'malware', 'attack', 'breach', 'threat',
            'security', 'cve', 'patch', 'fix', 'update', 'risk', 'critical'
        ]
        
        scored_sentences = []
        for i, sentence in enumerate(sentences):
            score = sum(1 for keyword in cyber_keywords if keyword in sentence.lower())
            score += 0.1 * (len(sentences) - i)  # Prefer earlier sentences
            scored_sentences.append((score, sentence))
        
        # Build result within token limit
        scored_sentences.sort(reverse=True, key=lambda x: x[0])
        result = ""
        
        for score, sentence in scored_sentences:
            test_result = result + sentence + ". "
            if self._estimate_tokens(test_result) <= max_tokens:
                result = test_result
            else:
                break
        
        return result.strip() or content[:max_tokens * 4]  # Fallback to character limit
    
    def assess_threat_severity(self, content: str) -> str:
        """Assess threat severity using ultra-efficient AI analysis"""
        
        # Preprocess content to minimize tokens while preserving severity indicators
        processed_content = self._preprocess_content(content, max_tokens=30)
        
        prompt = f"""Rate threat severity:

{processed_content}

Response: [Critical/High/Medium/Low]"""
        
        response = self._make_request(prompt, max_tokens=getattr(Config, 'MAX_SEVERITY_TOKENS', 10))
        
        if response:
            severity = response.strip().split()[0] if response.strip() else "Medium"
            valid_severities = ["Critical", "High", "Medium", "Low"]
            return severity if severity in valid_severities else "Medium"
        
        return self._fallback_severity_assessment(content)
    
    def _beautify_response(self, response: str) -> str:
        """Clean and beautify AI response"""
        # Remove excessive whitespace
        response = re.sub(r'\n\s*\n', '\n\n', response)
        
        # Fix emoji spacing
        response = re.sub(r'([🎯🔍⚠️🛡️📊])\s*', r'\1 ', response)
        
        # Ensure proper bullet point formatting
        response = re.sub(r'^\s*[•·]\s*', '• ', response, flags=re.MULTILINE)
        
        # Clean up markdown artifacts
        response = response.replace('**', '').replace('*', '')
        
        # Ensure sections are properly separated
        sections = [
            '🎯 THREAT CLASSIFICATION',
            '🔍 KEY FINDINGS', 
            '⚠️ IMPACT ASSESSMENT',
            '🛡️ DEFENSIVE ACTIONS',
            '📊 IOC SUMMARY'
        ]
        
        for section in sections:
            response = response.replace(section, f'\n{section}')
        
        return response.strip()
    
    def _generate_fallback_summary(self, threat_item: ThreatIntelItem) -> str:
        """Generate fallback summary when AI is unavailable"""
        ioc_count = sum(len(iocs) for iocs in threat_item.iocs.values())
        
        severity = self._fallback_severity_assessment(threat_item.description)
        
        return f"""
🎯 THREAT CLASSIFICATION
Type: Security Advisory
Severity: {severity}
Confidence: Medium

🔍 KEY FINDINGS
• Threat reported by {threat_item.source}
• Published: {threat_item.published_date}
• {ioc_count} indicators of compromise detected

⚠️ IMPACT ASSESSMENT
• Review threat details for affected systems
• Assess organizational exposure
• Monitor for related indicators

🛡️ DEFENSIVE ACTIONS
• Immediate: Review security controls
• Short-term: Update threat detection rules
• Monitoring: Watch for IOCs in network traffic

📊 IOC SUMMARY
• {ioc_count} indicators extracted
• AI analysis temporarily unavailable
"""
    
    def _fallback_severity_assessment(self, content: str) -> str:
        """Fallback severity assessment using keyword matching"""
        content_lower = content.lower()
        
        if hasattr(Config, 'HIGH_SEVERITY_KEYWORDS'):
            if any(keyword.lower() in content_lower for keyword in Config.HIGH_SEVERITY_KEYWORDS):
                return "High"
        else:
            # Legacy fallback keywords
            high_keywords = ['zero-day', 'critical vulnerability', 'active exploitation', 'worm', 'nation-state']
            if any(keyword in content_lower for keyword in high_keywords):
                return "High"
        
        # Medium severity fallback
        medium_keywords = ['vulnerability', 'exploit', 'malware', 'phishing']
        if any(keyword in content_lower for keyword in medium_keywords):
            return "Medium"
        
        return "Medium"
    
    def get_stats(self) -> Dict:
        """Get performance statistics with capacity analysis"""
        current_time = datetime.now()
        
        # Calculate total theoretical capacity
        total_rpm = 0
        available_rpm = 0
        
        for i, model in enumerate(Config.GEMINI_MODELS):
            model_rpm = model["rpm"] * len(Config.GEMINI_API_KEYS)  # RPM per model across all keys
            total_rpm += model_rpm
            
            # Check if model is currently available
            model_stats = self.model_stats[i]
            if model_stats.success_rate > 50:  # Consider available if >50% success rate
                available_rpm += model_rpm
        
        # Check key availability
        available_keys = 0
        rate_limited_keys = 0
        
        for key_stats in self.api_keys_stats:
            if not key_stats.is_rate_limited:
                available_keys += 1
            else:
                rate_limited_keys += 1
                
        return {
            "capacity_analysis": {
                "total_theoretical_rpm": total_rpm,
                "available_rpm": available_rpm,
                "utilization_percentage": round((total_rpm - available_rpm) / total_rpm * 100, 2) if total_rpm > 0 else 0
            },
            "api_keys": [
                {
                    "index": i,
                    "requests_made": stats.requests_made,
                    "daily_requests": stats.daily_requests,
                    "is_rate_limited": stats.is_rate_limited,
                    "rate_limit_reset": stats.rate_limit_reset_time.strftime("%H:%M:%S") if stats.rate_limit_reset_time else None,
                    "last_request": stats.last_request_time.strftime("%H:%M:%S") if stats.last_request_time else None
                }
                for i, stats in enumerate(self.api_keys_stats)
            ],
            "models": [
                {
                    "name": stats.name,
                    "requests_made": stats.requests_made,
                    "success_rate": round(stats.success_rate, 2),
                    "avg_response_time": round(stats.avg_response_time, 2),
                    "last_used": stats.last_used.strftime("%H:%M:%S") if stats.last_used else None,
                    "theoretical_rpm": Config.GEMINI_MODELS[i]["rpm"] * len(Config.GEMINI_API_KEYS)
                }
                for i, stats in enumerate(self.model_stats)
            ],
            "current_key_index": self.current_key_index,
            "current_model_index": self.current_model_index,
            "available_keys": available_keys,
            "rate_limited_keys": rate_limited_keys
        }
