import shap
import numpy as np

# Cache explainer to avoid recalculating trees per request
_explainer = None

def get_shap_explanation(rf_model, feature_array, feature_names):
    """
    Returns SHAP-based feature importance text for a single prediction.
    """
    global _explainer
    if _explainer is None:
        try:
            _explainer = shap.TreeExplainer(rf_model)
        except Exception as e:
            return f"SHAP Error: {str(e)}"
            
    try:
        # Calculate SHAP values for the specific query
        f_arr = np.array([feature_array])
        shap_values = _explainer.shap_values(f_arr)
        
        # Scikit-Learn RF returns list of arrays for multi-class. We want Class 1 (Malicious)
        if isinstance(shap_values, list):
            vals = shap_values[1][0]
        else:
            vals = shap_values[0]
            if len(vals.shape) > 1:
               vals = vals[:, 1] # SHAP 0.40+ compat
               
        # Sort features by highest impact pushing towards 1 (Malicious)
        impacts = list(zip(feature_names, vals))
        impacts.sort(key=lambda x: x[1], reverse=True)
        
        # Generate human textual explanation of top 3 features
        top_pos_features = [f"{name} (+{val*100:.1f}%)" for name, val in impacts[:3] if val > 0.01]
        
        if top_pos_features:
            explanation = " | ".join(top_pos_features) + " strongly contributed to malicious classification."
            return f"[XAI: SHAP] {explanation}"
        else:
            return ""
    except Exception as e:
        return ""
