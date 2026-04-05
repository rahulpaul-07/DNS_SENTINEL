import logging
from typing import Dict, Any

# Configure PIE Logging
logger = logging.getLogger("PIE_Engine")

class PriorityIntelligenceEngine:
    """
    PIE (Priority Intelligence Engine): Modular scoring system for DNSentinel.
    Transforms raw detection signals into actionable SOC priorities.
    """
    
    def __init__(self):
        # Configurable weights (Load from env or config file in production)
        self.weights = {
            "risk_score": 0.35,
            "intel_score": 0.25,
            "asset_value": 0.20,
            "behavior_score": 0.10,
            "attack_weight": 0.10
        }
        
        self.attack_type_weights = {
            "DGA": 40,
            "tunneling": 70,
            "exfiltration": 90,
            "normal": 0
        }

    def calculate_priority(
        self, 
        risk_score: float, 
        intel_score: float = 0, 
        asset_value: float = 50, 
        behavior_score: float = 0, 
        attack_type: str = "normal"
    ) -> Dict[str, Any]:
        """
        Calculates the PIE score and maps it to a priority level.
        """
        # 1. Resolve Attack Weight
        attack_weight = self.attack_type_weights.get(attack_type, 0)
        
        # 2. Weighted Sum Calculation
        pie_score = (
            (self.weights["risk_score"] * risk_score) +
            (self.weights["intel_score"] * intel_score) +
            (self.weights["asset_value"] * asset_value) +
            (self.weights["behavior_score"] * behavior_score) +
            (self.weights["attack_weight"] * attack_weight)
        )
        
        # Normalize to 0-100 range
        pie_score = min(max(pie_score, 0), 100)
        
        # 3. Priority Mapping
        if pie_score >= 85:
            priority = "CRITICAL"
        elif pie_score >= 70:
            priority = "HIGH"
        elif pie_score >= 50:
            priority = "MEDIUM"
        else:
            priority = "LOW"
            
        # 4. Generate Explainability String
        explanation = self._generate_explanation(pie_score, priority, intel_score, asset_value)
        
        return {
            "severity": risk_score,
            "priority_score": round(pie_score, 2),
            "priority": priority,
            "explanation": explanation
        }

    def _generate_explanation(self, score, priority, intel, asset) -> str:
        reasons = []
        if priority == "CRITICAL":
            reasons.append("Immediate containment required.")
        if intel > 80:
            reasons.append("Confirmed threat intelligence hit.")
        if asset > 80:
            reasons.append("High-value asset target.")
        
        base = f"PIE Score {round(score, 1)} ({priority})."
        return f"{base} {' '.join(reasons)}" if reasons else base

# Singleton Instance
pie_engine = PriorityIntelligenceEngine()
