"""ML Predictor v2 — XGBoost+LightGBM+CatBoost ensemble with domain reputation."""
import re, joblib, warnings
import numpy as np
from pathlib import Path
from django.conf import settings
from ml_engine.feature_extractor import extract_feature_vector, extract_features, FEATURE_NAMES

_model = _scaler = _encoder = None

SAFE_DOMAINS = {
    'google.com','google.co.in','google.co.uk','googleapis.com','gstatic.com',
    'github.com','github.io','githubusercontent.com','stackoverflow.com',
    'microsoft.com','azure.com','live.com','office.com','microsoftonline.com',
    'apple.com','icloud.com','amazon.com','amazon.co.uk','amazonaws.com',
    'youtube.com','youtu.be','facebook.com','instagram.com','twitter.com','x.com',
    'linkedin.com','reddit.com','wikipedia.org','wikimedia.org','medium.com',
    'npmjs.com','pypi.org','docker.com','gitlab.com','cloudflare.com',
    'paypal.com','stripe.com','shopify.com','ebay.com','netflix.com',
    'dropbox.com','notion.so','atlassian.com','slack.com','zoom.us',
    'twitch.tv','spotify.com','adobe.com','salesforce.com','oracle.com',
}

def _root(url):
    try:
        from urllib.parse import urlparse
        h = (urlparse(url if '://' in url else 'http://'+url).hostname or '').lower()
        p = h.replace('www.','').split('.')
        return '.'.join(p[-2:]) if len(p) >= 2 else h
    except Exception:
        return ''

def _has_structural_problems(feats):
    return bool(
        feats.get('has_ip') or
        feats.get('is_high_risk_tld') or
        feats.get('has_double_slash') or
        feats.get('num_subdomains', 0) > 3 or
        feats.get('has_at_symbol') or
        feats.get('has_punycode')
    )

def _load():
    global _model, _scaler, _encoder
    if _model is None:
        _model   = joblib.load(settings.ML_MODEL_PATH)
        _scaler  = joblib.load(settings.ML_SCALER_PATH)
        _encoder = joblib.load(settings.ML_LABEL_ENCODER_PATH)

def predict(url: str) -> dict:
    _load()
    raw = extract_features(url)

    # numpy array → scaler (fitted on numpy, so no warning)
    X  = np.array([[raw.get(n, 0) for n in FEATURE_NAMES]], dtype=np.float32)
    Xs = _scaler.transform(X)

    # Suppress the harmless "fitted without feature names" notice from LightGBM
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        pred_idx  = int(_model.predict(Xs)[0])
        pred_prob = _model.predict_proba(Xs)[0]

    classes = _encoder.classes_
    label   = classes[pred_idx]
    conf    = float(pred_prob[pred_idx])
    probs   = {c: round(float(p), 4) for c, p in zip(classes, pred_prob)}

    # Domain whitelist — trusted root domain + no structural red flags → force safe
    root          = _root(url)
    is_trusted    = (root in SAFE_DOMAINS or
                     any(root.endswith(s) for s in ('.gov', '.edu', '.ac.uk', '.gov.uk', '.gov.in')))
    whitelist_hit = is_trusted and not _has_structural_problems(raw)

    if whitelist_hit:
        label         = 'benign'
        conf          = 0.97
        probs = {c: 0.0 for c in classes}   # sab pehle zero
        probs['benign'] = 0.97
        ml_risk_score = 5
    else:
        BASE  = {'benign': 0,  'defacement': 20, 'malware': 55, 'phishing': 55}
        RANGE = {'benign': 15, 'defacement': 35, 'malware': 45, 'phishing': 45}
        ml_risk_score = int(min(100, BASE.get(label, 40) + conf * RANGE.get(label, 40)))

    return {
        'label':         label,
        'confidence':    round(conf, 4),
        'probabilities': probs,
        'features':      raw,
        'ml_risk_score': ml_risk_score,
        'whitelist_hit': whitelist_hit,
    }

def is_model_ready():
    try:
        return all(Path(p).exists() for p in [
            settings.ML_MODEL_PATH,
            settings.ML_SCALER_PATH,
            settings.ML_LABEL_ENCODER_PATH,
        ])
    except Exception:
        return False
