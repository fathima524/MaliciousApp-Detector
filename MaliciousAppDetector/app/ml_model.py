# app/ml_model.py
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# --- FEATURE EXTRACTION ---
def extract_features(report):
    try:
        rep = report["static_analysis"]["full_report"]
    except KeyError:
        rep = report.get("full_report", report)
    f = {}

    # Manifest
    mani = rep.get("manifest_analysis", {})
    findings = mani.get("manifest_findings", [])
    f["is_debuggable"] = int(any("debuggable=true" in x.get("title", "") for x in findings))
    f["allow_backup"] = int(any("allowBackup=true" in x.get("title", "") for x in findings))
    f["manifest_high"] = mani.get("manifest_summary", {}).get("high", 0)
    f["manifest_warning"] = mani.get("manifest_summary", {}).get("warning", 0)

    # Certificate
    cert = rep.get("certificate_analysis", {})
    f["is_signed_with_debug_cert"] = int("Android Debug" in cert.get("certificate_info", ""))
    f["num_certificate_findings_high"] = sum(1 for c in cert.get("certificate_findings", []) if c[0] == "high")

    # Binary protections
    binaries = rep.get("binary_analysis", [])
    if binaries:
        f["has_nx"] = int(all(b.get("nx", {}).get("is_nx", False) for b in binaries))
        f["has_pie"] = int(all("DSO" in str(b.get("pie", {}).get("is_pie", "")) for b in binaries))
        f["has_stack_canary"] = int(all(b.get("stack_canary", {}).get("has_canary", False) for b in binaries))
        f["has_relro_full"] = int(all("Full" in str(b.get("relocation_readonly", {}).get("relro", "")) for b in binaries))
        f["has_fortify"] = int(any(b.get("fortify", {}).get("is_fortified", False) for b in binaries))
    else:
        for k in ["has_nx","has_pie","has_stack_canary","has_relro_full","has_fortify"]:
            f[k] = 0

    # Permissions
    perms = rep.get("permissions", {})
    f["num_dangerous_permissions"] = sum(1 for p in perms.values() if p.get("status") == "dangerous")

    # Code analysis
    code = rep.get("code_analysis", {}).get("summary", {})
    f["code_high"] = code.get("high", 0)
    f["code_warning"] = code.get("warning", 0)

    # Dynamic analysis
    dyn = report.get("dynamic_analysis", {}).get("behavior", {})
    f["dynamic_permission_requests"] = dyn.get("permission_requests", 0)
    f["dynamic_native_code_calls"] = dyn.get("native_code", 0)

    # Fill missing
    for k in f:
        if f[k] is None:
            f[k] = 0
    return f


# --- TRAINING FUNCTION (for dev/test use only) ---
def train_dummy_model(base_features, samples=200):
    rows = []
    for i in range(samples):
        r = base_features.copy()
        for k in ["is_debuggable","allow_backup","is_signed_with_debug_cert",
                  "has_nx","has_pie","has_stack_canary","has_relro_full","has_fortify"]:
            r[k] = np.random.choice([0,1], p=[0.7,0.3])
        r["num_dangerous_permissions"] = np.random.randint(0, 12)
        r["manifest_high"] = np.random.randint(0, 5)
        r["manifest_warning"] = np.random.randint(0, 10)
        r["code_high"] = np.random.randint(0, 4)
        r["code_warning"] = np.random.randint(0, 5)
        r["dynamic_permission_requests"] = np.random.randint(0, 30)
        r["dynamic_native_code_calls"] = np.random.randint(0, 100)
        r["num_certificate_findings_high"] = np.random.randint(0, 3)
        r["label"] = int(
            r["is_signed_with_debug_cert"] or
            r["is_debuggable"] or
            r["num_dangerous_permissions"] > 6 or
            r["code_high"] > 1
        )
        rows.append(r)
    df = pd.DataFrame(rows)
    X = df.drop(columns=["label"])
    y = df["label"]

    model = RandomForestClassifier(n_estimators=120, random_state=42)
    model.fit(X, y)
    return model


# --- PREDICT FUNCTION ---
def classify_report(report, model):
    features = extract_features(report)
    df = pd.DataFrame([features])
    pred = model.predict(df)[0]
    prob = model.predict_proba(df)[0][1]
    return {
        "prediction": int(pred),
        "probability": float(prob),
        "label": "malicious" if pred == 1 else "benign",
        "features": features
    }
