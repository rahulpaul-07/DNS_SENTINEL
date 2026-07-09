"""Contract tests for the ML prediction layer (backend/model.py).

We don't assert exact model outputs (those depend on the trained artifacts),
but we lock in the public contract the API depends on: the 22-feature vector
ordering and the shape/type of predict()'s return value.

The predict path pulls in the full ML stack (scikit-learn, shap). When those
optional/heavy deps aren't installed we skip rather than fail, so the fast
feature/risk tests still run everywhere.
"""
import pytest

from features import extract_features

pytest.importorskip("sklearn", reason="scikit-learn not installed")
pytest.importorskip("shap", reason="shap not installed")

from model import predict  # noqa: E402  (import after skip guards)


# The 22-feature order the API builds its vector in (see main.py analyze_dns).
FEATURE_ORDER = [
    "entropy", "length", "subdomain_length", "ngram_score", "frequency",
    "consonant_ratio", "digit_ratio", "unique_char", "vowels_consonant_ratio",
    "max_continuous_numeric_len", "max_continuous_alphabet_len",
    "max_continuous_consonants_len", "max_continuous_same_char",
    "upper_count", "lower_count", "special_count", "labels", "labels_max",
    "labels_average", "entropy_to_length_ratio", "high_entropy_flag",
    "domain_complexity",
]


def _vector_for(domain: str):
    feats = extract_features({"query": domain})
    feats["frequency"] = 1
    return [feats[name] for name in FEATURE_ORDER]


def test_feature_vector_has_22_dimensions():
    assert len(_vector_for("example.com")) == 22


def test_predict_returns_four_part_contract():
    label, confidence, iso, shap_text = predict(
        _vector_for("example.com"), domain="example.com"
    )
    assert label in (0, 1)
    assert 0.0 <= confidence <= 1.0
    assert iso in (-1, 1)
    assert isinstance(shap_text, str)


def test_predict_is_deterministic_for_same_input():
    v = _vector_for("google.com")
    first = predict(list(v), domain="google.com")[0]
    second = predict(list(v), domain="google.com")[0]
    assert first == second
