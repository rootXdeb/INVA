import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import json
import os

MODEL_PATH   = os.path.join(os.path.dirname(__file__), "model.pkl")
ENCODER_PATH = os.path.join(os.path.dirname(__file__), "encoder.pkl")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "model_metrics.json")

# Synthetic training data based on real CVE/CVSS patterns
# Columns: port, service_code, is_legacy, is_encrypted, requires_auth,
#          cvss_score, has_known_exploit, dangerous_port -> risk_label
TRAINING_DATA = [
    # CRITICAL
    (23,  0, 1, 0, 0, 9.8, 1, 1, "CRITICAL"),   # Telnet
    (445, 1, 0, 0, 0, 10.0,1, 1, "CRITICAL"),   # SMB (EternalBlue)
    (6379,2, 0, 0, 0, 10.0,1, 1, "CRITICAL"),   # Redis no-auth
    (27017,3,0, 0, 0, 10.0,1, 1, "CRITICAL"),   # MongoDB no-auth
    (5900,4, 0, 0, 0, 9.8, 1, 1, "CRITICAL"),   # VNC no-auth
    (2375,5, 0, 0, 0, 10.0,1, 1, "CRITICAL"),   # Docker daemon
    (9200,6, 0, 0, 0, 9.8, 1, 1, "CRITICAL"),   # Elasticsearch no-auth
    (11211,7,0, 0, 0, 9.8, 1, 1, "CRITICAL"),   # Memcached
    (23,  0, 1, 0, 0, 9.5, 1, 1, "CRITICAL"),
    (445, 1, 0, 0, 0, 9.8, 1, 1, "CRITICAL"),

    # HIGH
    (21,  8, 1, 0, 0, 8.5, 1, 0, "HIGH"),       # FTP plaintext
    (3389,9, 0, 0, 1, 9.8, 1, 1, "HIGH"),        # RDP
    (1433,10,0, 0, 1, 8.8, 1, 1, "HIGH"),        # MSSQL
    (3306,11,0, 0, 1, 9.8, 1, 1, "HIGH"),        # MySQL exposed
    (5432,12,0, 0, 1, 8.5, 1, 1, "HIGH"),        # PostgreSQL exposed
    (135, 13,1, 0, 0, 9.3, 1, 1, "HIGH"),        # RPC
    (139, 14,1, 0, 0, 9.0, 1, 1, "HIGH"),        # NetBIOS
    (25,  15,0, 0, 0, 7.5, 1, 0, "HIGH"),        # SMTP relay
    (111, 16,1, 0, 0, 8.1, 1, 1, "HIGH"),        # RPC portmapper
    (512, 17,1, 0, 0, 9.3, 1, 1, "HIGH"),        # rexec
    (513, 18,1, 0, 0, 9.3, 1, 1, "HIGH"),        # rlogin
    (514, 19,1, 0, 0, 9.3, 1, 1, "HIGH"),        # rsh
    (4444,20,0, 0, 0, 9.8, 1, 1, "HIGH"),        # Metasploit default
    (31337,21,0,0, 0, 9.8, 1, 1, "HIGH"),        # Back Orifice
    (21,  8, 1, 0, 0, 7.5, 1, 0, "HIGH"),
    (3389,9, 0, 0, 1, 8.5, 1, 1, "HIGH"),
    (3306,11,0, 0, 1, 8.0, 1, 1, "HIGH"),

    # MEDIUM
    (80,  22,0, 0, 0, 7.5, 1, 0, "MEDIUM"),     # HTTP
    (8080,23,0, 0, 0, 6.5, 1, 0, "MEDIUM"),     # HTTP-alt
    (110, 24,1, 0, 1, 6.5, 1, 0, "MEDIUM"),     # POP3
    (143, 25,0, 0, 1, 6.5, 0, 0, "MEDIUM"),     # IMAP
    (53,  26,0, 0, 0, 6.8, 0, 0, "MEDIUM"),     # DNS
    (161, 27,0, 0, 0, 7.5, 1, 0, "MEDIUM"),     # SNMP
    (1521,28,0, 0, 1, 7.5, 1, 0, "MEDIUM"),     # Oracle DB
    (5000,29,0, 0, 0, 6.5, 0, 0, "MEDIUM"),     # UPnP/dev
    (8443,30,0, 1, 0, 5.5, 0, 0, "MEDIUM"),     # HTTPS-alt
    (2049,31,1, 0, 0, 7.5, 1, 0, "MEDIUM"),     # NFS
    (873, 32,0, 0, 0, 7.5, 1, 0, "MEDIUM"),     # rsync
    (69,  33,1, 0, 0, 6.5, 1, 0, "MEDIUM"),     # TFTP
    (79,  34,1, 0, 0, 5.3, 1, 0, "MEDIUM"),     # Finger
    (80,  22,0, 0, 0, 6.5, 0, 0, "MEDIUM"),
    (8080,23,0, 0, 0, 5.5, 0, 0, "MEDIUM"),
    (80,  22,0, 0, 0, 7.0, 1, 0, "MEDIUM"),
    (110, 24,1, 0, 1, 7.0, 1, 0, "MEDIUM"),
    (53,  26,0, 0, 0, 5.5, 0, 0, "MEDIUM"),
    (161, 27,0, 0, 0, 6.5, 0, 0, "MEDIUM"),

    # LOW
    (22,  35,0, 1, 1, 5.3, 0, 0, "LOW"),        # SSH (modern)
    (443, 36,0, 1, 0, 4.0, 0, 0, "LOW"),        # HTTPS
    (587, 37,0, 1, 1, 3.5, 0, 0, "LOW"),        # SMTP submission (TLS)
    (993, 38,0, 1, 1, 3.5, 0, 0, "LOW"),        # IMAPS
    (995, 39,0, 1, 1, 3.5, 0, 0, "LOW"),        # POP3S
    (636, 40,0, 1, 1, 4.0, 0, 0, "LOW"),        # LDAPS
    (8443,30,0, 1, 1, 3.0, 0, 0, "LOW"),        # HTTPS-alt secure
    (22,  35,0, 1, 1, 4.0, 0, 0, "LOW"),
    (443, 36,0, 1, 0, 3.5, 0, 0, "LOW"),
    (22,  35,0, 1, 1, 5.0, 0, 0, "LOW"),
    (443, 36,0, 1, 0, 4.5, 0, 0, "LOW"),
    (587, 37,0, 1, 1, 4.0, 0, 0, "LOW"),

    # Extra variations for robustness
    (8080,23,0, 0, 0, 7.5, 1, 0, "MEDIUM"),
    (3389,9, 0, 0, 1, 7.0, 0, 1, "HIGH"),
    (5432,12,0, 0, 1, 6.5, 0, 0, "MEDIUM"),
    (21,  8, 1, 0, 0, 6.0, 0, 0, "MEDIUM"),
    (23,  0, 1, 0, 0, 8.0, 0, 1, "CRITICAL"),
    (9200,6, 0, 0, 0, 8.5, 0, 1, "CRITICAL"),
    (27017,3,0, 0, 0, 8.0, 0, 1, "HIGH"),
    (6379,2, 0, 0, 0, 8.5, 0, 1, "CRITICAL"),
    (1433,10,0, 0, 1, 7.5, 0, 1, "HIGH"),
    (3306,11,0, 0, 1, 7.0, 0, 1, "HIGH"),
    (25,  15,0, 0, 0, 6.5, 0, 0, "MEDIUM"),
    (53,  26,0, 0, 0, 7.5, 1, 0, "MEDIUM"),
    (161, 27,0, 0, 0, 8.0, 1, 1, "HIGH"),
    (2375,5, 0, 0, 0, 9.0, 1, 1, "CRITICAL"),
    (5900,4, 0, 0, 0, 8.5, 0, 1, "HIGH"),
    (11211,7,0, 0, 0, 8.0, 0, 1, "CRITICAL"),
]


FEATURE_NAMES = [
    "Port Number", "Service Type", "Legacy Protocol", "Encrypted",
    "Auth Required", "CVSS Score", "Known Exploit", "Dangerous Port",
]


def train():
    data = np.array(TRAINING_DATA)
    X = data[:, :8].astype(float)
    y = data[:, 8]

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )

    clf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    accuracy = round(accuracy_score(y_test, y_pred) * 100, 1)

    # Cross-validation accuracy (5-fold)
    cv_scores = cross_val_score(clf, X, y_enc, cv=5, scoring="accuracy")
    cv_accuracy = round(float(cv_scores.mean()) * 100, 1)
    cv_std      = round(float(cv_scores.std()) * 100, 1)

    report_dict = classification_report(
        y_test, y_pred, target_names=le.classes_, output_dict=True
    )
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("=== ML Model Training Report ===")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print(f"Test accuracy: {accuracy}%  |  CV accuracy: {cv_accuracy}% ± {cv_std}%")

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)

    metrics = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 200,
        "max_depth": 10,
        "n_training_samples": int(len(X_train)),
        "n_test_samples": int(len(X_test)),
        "n_features": int(X.shape[1]),
        "feature_names": FEATURE_NAMES,
        "classes": list(le.classes_),
        "test_accuracy": accuracy,
        "cv_accuracy": cv_accuracy,
        "cv_std": cv_std,
        "classification_report": report_dict,
        "confusion_matrix": cm,
        "feature_importances": [
            round(float(v), 4) for v in clf.feature_importances_
        ],
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"Model saved to {MODEL_PATH}")
    print(f"Metrics saved to {METRICS_PATH}")
    return clf, le


if __name__ == "__main__":
    train()
