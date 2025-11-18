import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ---------------- STEP 1: EXTRACT FEATURES ----------------
def extract_features(report):
    try:
        rep = report["static_analysis"]["full_report"]
    except KeyError:
        rep = report.get("full_report", report)
    f = {}

    # Manifest Analysis
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

# ---------------- STEP 2: LOAD YOUR BASE REPORT ----------------
base_file = r"C:\MaliciousAppDetector\model\reports\20251109_144930_ebbab1c3.json"
with open(base_file, "r") as f:
    data = json.load(f)
base_feats = extract_features(data)

print("\n✅ Extracted base features:")
for k, v in base_feats.items():
    print(f"  {k}: {v}")

# ---------------- STEP 3: GENERATE SYNTHETIC TRAINING DATA ----------------
rows = []
for i in range(200):
    r = base_feats.copy()
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
    # Heuristic label
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

# ---------------- STEP 4: TRAIN RANDOM FOREST ----------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
model = RandomForestClassifier(n_estimators=120, random_state=42)
model.fit(X_train, y_train)
print("\n✅ Model trained successfully.")
print(classification_report(y_test, model.predict(X_test)))

# ---------------- STEP 5: PREDICT ON ANOTHER REPORT ----------------
test_file = r"C:\MaliciousAppDetector\model\reports\20251110_040552_effd23ff.json"
with open(test_file, "r") as f:
    test_data = json.load(f)
test_feats = extract_features(test_data)
test_df = pd.DataFrame([test_feats])
pred = model.predict(test_df)[0]
prob = model.predict_proba(test_df)[0][1]

print("\n===== PREDICTION RESULT =====")
print(json.dumps(test_feats, indent=2))
print(f"\nPrediction: {'⚠️ MALICIOUS' if pred==1 else '✅ BENIGN'}")
print(f"Malicious probability: {prob:.2f}")
