MITRE_MAPPING = {
    "T1071.004": {
        "Name": "Application Layer Protocol: DNS",
        "Description": "Adversaries may communicate with a C2 server using DNS for tunneling. Typically detected via high domain entropy indicating encoded blocks.",
        "Mitigation": "Implement Strict DNS firewall rules blocking lengthy subdomains. Route critical traffic through verified sinkholes."
    },
    "T1041": {
        "Name": "Exfiltration Over C2 Channel",
        "Description": "Rapid exfiltration detected over the current channel. Characterized by abnormal bursts of query frequency from a single internal IP.",
        "Mitigation": "Isolate the source endpoint IP immediately. Block external unverified name servers on edge firewalls."
    },
    "T1568": {
        "Name": "Dynamic Resolution / DGA",
        "Description": "Adversaries may use Domain Generation Algorithms (DGA) to evade blacklists. Identified by abnormally low n-gram structural probability.",
        "Mitigation": "Enable predictive DGA-blocking on internal DNS resolvers. Analyze endpoint processes calling out to unresolved domains."
    }
}

def map_threat(features, pred_label, iso_pred):
    """Maps rigorous ML classifications to MITRE ATT&CK techniques with mitigations."""
    if pred_label == 0 and iso_pred == 1:
        return None
    
    mapping = {}
    entropy = features.get('entropy', 0)
    freq = features.get('frequency', 0)
    ngram_score = features.get('ngram_score', 1.0)
    unique_char = features.get('unique_char', 0)
    
    if entropy > 3.8 or unique_char > 0.8:
        mapping["T1071.004"] = MITRE_MAPPING["T1071.004"]
        
    if ngram_score < 0.01 or (iso_pred == -1 and entropy > 3.5):
         mapping["T1568"] = MITRE_MAPPING["T1568"]
    
    if freq > 30 and entropy > 3.0:
        mapping["T1041"] = MITRE_MAPPING["T1041"]
        
    return mapping

def generate_explanation(features, pred_label, iso_pred, risk_score):
    """Generates an intelligent human-readable explanation mapping deep protocol features."""
    if risk_score <= 30:
        return "Standard benign DNS resolution. Traffic parameters and protocol structure match human-normal baselines."
    
    reasons = []
    
    if iso_pred == -1:
        reasons.append("[Anomaly] Isolation Forest flagged this packet structure as a zero-day structural anomaly.")
        
    if features.get('subdomain_length', 0) > 20 and features.get('entropy', 0) > 4.0:
        reasons.append(f"[Protocol] Subdomain contains high entropy encoded data typical of tunneling ({features['entropy']:.2f}).")
    elif features.get('entropy', 0) > 4.0:
        reasons.append(f"[Payload] High Shannon Entropy ({features['entropy']:.2f}) indicates encrypted data packing.")
        
    if features.get('labels_max', 0) > 40:
        reasons.append(f"[Protocol] Unusually long DNS label detected ({features['labels_max']} chars). Strong indicator of base64 tunneling limits.")
        
    if features.get('ngram_score', 1.0) < 0.01:
        reasons.append(f"[Structural] Domain completely lacks standard human-readable n-grams ({features['ngram_score']:.4f}). Likely an algorithmic DGA generated domain.")
        
    if features.get('frequency', 0) > 40:
        reasons.append(f"[Behavioral] Frequent queries to different or deeply nested domains from the same source IP ({features['frequency']} req/min) detected.")
        
    if features.get('max_continuous_consonants_len', 0) > 7:
        reasons.append(f"[Structural] Dense consonant blocks ({features['max_continuous_consonants_len']} in a row) heavily deviates from valid naming structures.")

    if not reasons:
        reasons.append("Random Forest Ensemble detected suspicious statistical ML deviation mapping to trained malicious attack architectures.")
        
    return " ".join(reasons)
