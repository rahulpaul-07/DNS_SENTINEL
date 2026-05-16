import time
import yaml
import numpy as np
import asyncio
import os
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
from datetime import datetime

logger = logging.getLogger("DNSentinel.RiskEngine")

class RiskTier(Enum):
    MONITOR = "Low"
    ALERT = "Medium"
    BLOCK = "High"
    CRITICAL = "Critical"

@dataclass
class RiskProfile:
    source_ip: str
    current_score: float = 0.0
    score_history: deque = field(default_factory=lambda: deque(maxlen=100))
    query_history: deque = field(default_factory=lambda: deque(maxlen=500))
    tier: RiskTier = RiskTier.MONITOR
    last_seen: datetime = field(default_factory=datetime.now)
    total_queries: int = 0

class RiskEngine:
    def __init__(self, config_path: str = "risk_baseline.yaml"):
        self.profiles: Dict[str, RiskProfile] = {}
        self.lock = asyncio.Lock()
        
        # Default config in case file is missing
        self.config = {
            'weights': {'ml': 0.5, 'behavior': 0.3, 'intel': 0.2},
            'sensitivity': {'k_factor': 2.0}
        }
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            # Create default config if it doesn't exist
            with open(config_path, 'w') as f:
                yaml.dump(self.config, f)

        self.w_ml = self.config['weights']['ml']
        self.w_behavior = self.config['weights']['behavior']
        self.w_intel = self.config['weights']['intel']
        self.k_factor = self.config['sensitivity']['k_factor']

    def _compute_behavior_score(self, profile: RiskProfile) -> float:
        now = time.time()
        five_min_ago = now - 300
        recent = [q for q in profile.query_history if q[0] > five_min_ago]
        
        if not recent: return 0.0
        
        # Velocity score (queries per minute)
        velocity = len(recent) / 5.0
        v_score = min(velocity / 120.0, 1.0) # Normalized to 120 qpm
        
        # Entropy/Unique ratio
        unique_domains = len(set(q[1] for q in recent))
        u_score = unique_domains / len(recent)
        
        return (v_score * 0.6) + (u_score * 0.4)

    async def score(self, source_ip: str, domain: str, ml_score: float, intel_score: float = 0.0) -> Tuple[float, str]:
        """
        Adaptive Scoring Logic
        Returns: (final_score 0-100, risk_level string)
        """
        async with self.lock:
            if source_ip not in self.profiles:
                self.profiles[source_ip] = RiskProfile(source_ip=source_ip)
            
            p = self.profiles[source_ip]
            p.last_seen = datetime.now()
            p.total_queries += 1
            p.query_history.append((time.time(), domain))
            
            behavior_score = self._compute_behavior_score(p)
            
            # Weighted Combine (0-1 range)
            combined_base = (self.w_ml * ml_score) + \
                           (self.w_behavior * behavior_score) + \
                           (self.w_intel * intel_score)
            
            final_score_raw = combined_base * 100
            
            # Dynamic Thresholding
            tier = RiskTier.MONITOR
            if len(p.score_history) > 15:
                history = list(p.score_history)
                mean = np.mean(history)
                std = np.std(history)
                dynamic_threshold = mean + (self.k_factor * std)
                
                if final_score_raw > dynamic_threshold * 1.5 or final_score_raw > 85:
                    tier = RiskTier.CRITICAL
                elif final_score_raw > dynamic_threshold * 1.2 or final_score_raw > 65:
                    tier = RiskTier.BLOCK
                elif final_score_raw > dynamic_threshold:
                    tier = RiskTier.ALERT
            else:
                # Static fallbacks for initial profiling
                if final_score_raw > 80: tier = RiskTier.CRITICAL
                elif final_score_raw > 50: tier = RiskTier.BLOCK
                elif final_score_raw > 25: tier = RiskTier.ALERT

            p.current_score = final_score_raw
            p.score_history.append(final_score_raw)
            p.tier = tier
            
            return round(final_score_raw, 1), tier.value

# Singleton
risk_engine = RiskEngine()
