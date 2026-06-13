import os
import json
import numpy as np
import joblib

MODEL_PATH   = os.path.join(os.path.dirname(__file__), "model.pkl")
ENCODER_PATH = os.path.join(os.path.dirname(__file__), "encoder.pkl")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "model_metrics.json")

SERVICE_CODE = {
    "TELNET": 0, "SMB": 1, "REDIS": 2, "MONGODB": 3, "VNC": 4,
    "DOCKER": 5, "ELASTICSEARCH": 6, "MEMCACHED": 7, "FTP": 8,
    "RDP": 9, "MSSQL": 10, "MYSQL": 11, "POSTGRESQL": 12,
    "RPC": 13, "NETBIOS": 14, "SMTP": 15, "PORTMAPPER": 16,
    "REXEC": 17, "RLOGIN": 18, "RSH": 19, "METASPLOIT": 20,
    "BACKDOOR": 21, "HTTP": 22, "HTTP-ALT": 23, "POP3": 24,
    "IMAP": 25, "DNS": 26, "SNMP": 27, "ORACLE": 28,
    "UPNP": 29, "HTTPS-ALT": 30, "NFS": 31, "RSYNC": 32,
    "TFTP": 33, "FINGER": 34, "SSH": 35, "HTTPS": 36,
    "SMTP-TLS": 37, "IMAPS": 38, "POP3S": 39, "LDAPS": 40,
}

DANGEROUS_PORTS = {23, 445, 6379, 27017, 5900, 2375, 9200, 11211,
                   3389, 1433, 135, 139, 512, 513, 514, 4444, 31337}

LEGACY_SERVICES     = {"FTP", "TELNET", "POP3", "RPC", "NETBIOS",
                        "REXEC", "RLOGIN", "RSH", "TFTP", "FINGER", "NFS"}
ENCRYPTED_SERVICES  = {"HTTPS", "SSH", "IMAPS", "POP3S", "SMTP-TLS", "LDAPS", "HTTPS-ALT"}
AUTH_REQUIRED       = {"SSH", "MSSQL", "MYSQL", "POSTGRESQL", "ORACLE",
                       "RDP", "FTP", "POP3", "IMAP", "IMAPS", "POP3S"}

FEATURE_NAMES = [
    "Port Number", "Service Type", "Legacy Protocol", "Encrypted",
    "Auth Required", "CVSS Score", "Known Exploit", "Dangerous Port",
]

_model     = None
_encoder   = None
_explainer = None


def _load():
    global _model, _encoder
    if _model is None:
        if os.path.exists(MODEL_PATH) and os.path.exists(METRICS_PATH):
            _model   = joblib.load(MODEL_PATH)
            _encoder = joblib.load(ENCODER_PATH)
        else:
            from ml.train_model import train
            _model, _encoder = train()


def _get_explainer():
    global _explainer
    if _explainer is None:
        _load()
        try:
            import shap
            _explainer = shap.TreeExplainer(_model)
        except Exception:
            _explainer = None
    return _explainer


def _build_features(port: int, service: str, cvss_score: float, has_known_cve: bool):
    service_upper  = service.upper().replace(" ", "-")
    service_code   = SERVICE_CODE.get(service_upper, 22)
    is_legacy      = 1 if service_upper in LEGACY_SERVICES else 0
    is_encrypted   = 1 if service_upper in ENCRYPTED_SERVICES else 0
    requires_auth  = 1 if service_upper in AUTH_REQUIRED else 0
    is_dangerous   = 1 if port in DANGEROUS_PORTS else 0
    has_exploit    = 1 if has_known_cve else 0
    return np.array([[port, service_code, is_legacy, is_encrypted,
                      requires_auth, cvss_score, has_exploit, is_dangerous]])


def predict(port: int, service: str, cvss_score: float = 5.0,
            has_known_cve: bool = False) -> dict:
    _load()
    features  = _build_features(port, service, cvss_score, has_known_cve)
    pred_enc  = _model.predict(features)[0]
    proba     = _model.predict_proba(features)[0]
    risk_label = _encoder.inverse_transform([pred_enc])[0]
    confidence = round(float(max(proba)) * 100, 1)

    return {
        "predicted_risk":      risk_label,
        "confidence":          confidence,
        "exploit_probability": round(float(max(proba)), 3),
    }


def explain(port: int, service: str, cvss_score: float = 5.0,
            has_known_cve: bool = False) -> list:
    """Return SHAP-based feature contributions for a single prediction."""
    _load()
    explainer = _get_explainer()
    if explainer is None:
        return []

    features  = _build_features(port, service, cvss_score, has_known_cve)
    pred_enc  = int(_model.predict(features)[0])

    try:
        shap_vals = explainer.shap_values(features)
        # shap_vals is a list [n_classes] of arrays (n_samples, n_features)
        if isinstance(shap_vals, list):
            sv = np.array(shap_vals[pred_enc][0])
        else:
            # Newer SHAP may return (n_samples, n_features, n_classes)
            sv = np.array(shap_vals[0, :, pred_enc])
    except Exception:
        return []

    total = float(np.sum(np.abs(sv))) or 1.0
    contributions = []
    for name, val in zip(FEATURE_NAMES, sv):
        contributions.append({
            "feature":          name,
            "shap_value":       round(float(val), 4),
            "contribution_pct": round(abs(float(val)) / total * 100, 1),
            "direction":        "increases_risk" if val > 0 else "decreases_risk",
        })
    contributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
    return contributions


def get_model_metrics() -> dict:
    """Load and return saved model training metrics."""
    if not os.path.exists(METRICS_PATH):
        _load()  # triggers training which saves metrics
    try:
        with open(METRICS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}
