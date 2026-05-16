// Simple JS implementation of features.py for fallback scoring
export function extractFeatures(domain) {
    const queryLower = domain.toLowerCase();
    const parts = queryLower.split('.');
    const subdomain = parts.length > 2 ? parts[0] : '';
    
    // 1. Structural Randomness (Entropy)
    const entropy = calculateEntropy(queryLower);
    
    // 2. Length
    const length = queryLower.length;
    const subdomain_length = subdomain.length;
    
    // 3. Ratios
    const consonants = queryLower.match(/[^aeiou0-9.-]/g) || [];
    const digits = queryLower.match(/[0-9]/g) || [];
    const consonant_ratio = consonants.length / (length || 1);
    const digit_ratio = digits.length / (length || 1);
    
    // 4. Counts
    const labels = parts.length;
    const labels_max = Math.max(...parts.map(p => p.length), 0);
    
    return {
        entropy,
        length,
        subdomain_length,
        consonant_ratio,
        digit_ratio,
        labels,
        labels_max
    };
}

function calculateEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
        const char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    return Object.values(frequencies).reduce((sum, freq) => {
        const p = freq / len;
        return sum - (p * Math.log2(p));
    }, 0);
}

export function calculateFallbackScore(features, domain) {
    // Ported PIE (Priority Intelligence Engine) Logic
    let risk_score = 0;
    
    // Calculate raw risk based on DNS features
    risk_score += (features.entropy || 0) * 12; // e.g. 4.0 -> 48
    risk_score += ((features.length || 0) > 20 ? 20 : (features.length || 0));
    risk_score += ((features.digit_ratio || 0) * 35);
    risk_score = Math.min(risk_score, 100);
    
    // Realistic simulation data for demo purposes
    const intel_score = Math.random() > 0.85 ? 90 : Math.random() * 30; // Occasional threat intel hit
    const behavior_score = Math.random() * 40;
    const asset_value = 60; // Standard workstation
    
    // Determine simulated attack type
    let attack_weight = 0;
    let attack_type = "normal";
    if ((features.entropy || 0) > 4.2 || (features.length || 0) > 25) {
        attack_type = "DGA";
        attack_weight = 40;
    }
    
    // PIE Weights
    const weights = { risk_score: 0.35, intel_score: 0.25, asset_value: 0.20, behavior_score: 0.10, attack_weight: 0.10 };
    
    // Calculate final PIE score
    let pie_score = (
        (weights.risk_score * risk_score) +
        (weights.intel_score * intel_score) +
        (weights.asset_value * asset_value) +
        (weights.behavior_score * behavior_score) +
        (weights.attack_weight * attack_weight)
    );
    
    pie_score = Math.min(Math.max(pie_score, 0), 100);
    
    let priority = "LOW";
    if (pie_score >= 85) priority = "CRITICAL";
    else if (pie_score >= 70) priority = "BLOCK";
    else if (pie_score >= 50) priority = "ALERT";
    else priority = "MONITOR";
    
    return { 
        ml_score: pie_score / 100, 
        isolation_score: 1, 
        final_score: pie_score,
        shap_reason: `PIE Engine: ${pie_score.toFixed(1)} (${priority}). Risk: ${risk_score.toFixed(1)}, Intel: ${intel_score.toFixed(1)}`
    };
}
