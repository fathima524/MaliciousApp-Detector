from fastapi import FastAPI, UploadFile, File
import tempfile
import asyncio
import json
import os
from datetime import datetime
import uuid
from app.ml_model import extract_features, train_dummy_model, classify_report

from supabase import create_client
from dotenv import load_dotenv
import httpx

from app.dynamic_analyzer import DynamicAnalyzer

load_dotenv()

app = FastAPI(title="Malicious App Detector")

MOBSF_URL = os.getenv("MOBSF_URL")
API_KEY = os.getenv("MOBSF_API_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

assert MOBSF_URL and API_KEY and SUPABASE_URL and SUPABASE_KEY, "Set all env vars"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
dynamic_analyzer = DynamicAnalyzer()

async def upload_and_get_report_from_file(apk_path, filename):
    headers = {"Authorization": API_KEY}
    async with httpx.AsyncClient(timeout=300.0) as client:
        with open(apk_path, "rb") as f:
            files = {"file": (filename, f, "application/octet-stream")}
            upload_resp = await client.post(f"{MOBSF_URL}/api/v1/upload", files=files, headers=headers)

        if upload_resp.status_code != 200:
            return {"filename": filename, "error": f"Upload failed: {upload_resp.text}", "status": "failed", "stage_log": [f"Upload failed: {upload_resp.text}"]}

        upload_data = upload_resp.json()
        md5_hash = upload_data.get("hash")

        if not md5_hash:
            return {"filename": filename, "error": "No hash received from MobSF", "status": "failed", "stage_log": ["No hash received from MobSF"]}

        # Trigger scan explicitly after upload
        scan_resp = await client.post(
            f"{MOBSF_URL}/api/v1/scan",
            headers=headers,
            data={"hash": md5_hash}
        )

        if scan_resp.status_code != 200:
            return {"filename": filename, "error": f"Scan trigger failed: {scan_resp.text}", "status": "failed", "stage_log": [f"Scan trigger failed: {scan_resp.text}"]}

        max_attempts = 60
        poll_interval = 10
        stage_log = ["Upload successful, scanning started."]

        for attempt in range(max_attempts):
            await asyncio.sleep(poll_interval)
            try:
                report_resp = await client.post(
                    f"{MOBSF_URL}/api/v1/report_json",
                    headers=headers,
                    data={"hash": md5_hash}
                )
                if report_resp.status_code == 200:
                    report = report_resp.json()
                    elapsed_time = (attempt + 1) * poll_interval
                    stage_log.append(f"✓ Report ready for {filename} in {elapsed_time}s")
                    return {
                        "filename": filename,
                        "hash": md5_hash,
                        "full_report": report,
                        "status": "success",
                        "scan_duration": elapsed_time,
                        "stage_log": stage_log
                    }
            except Exception as e:
                stage_log.append(f"Poll attempt {attempt + 1} failed: {e}")
                continue

        stage_log.append("Report not ready after 600 seconds of polling.")
        return {
            "filename": filename,
            "error": "Report not ready after 600 seconds of polling",
            "status": "timeout",
            "stage_log": stage_log
        }


@app.post("/analyze_full/")
async def analyze_full(file: UploadFile = File(...)):
    filename = file.filename
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        content = await file.read()
        tmp.write(content)
        apk_path = tmp.name

    try:
        # --- Run Static and Dynamic Analysis ---
        static_result = await upload_and_get_report_from_file(apk_path, filename)
        dynamic_result = await asyncio.to_thread(dynamic_analyzer.analyze_apk, apk_path)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        base_filename = filename.replace('.apk', '').replace('.APK', '')
        bucket_path = f"combined-analysis/{base_filename}/{timestamp}_{unique_id}.json"

        # --- Combine Results ---
        combined_report = {
            "filename": filename,
            "timestamp": datetime.utcnow().isoformat(),
            "static_analysis": static_result,
            "dynamic_analysis": dynamic_result,
        }

        # --- Run ML Classification ---
        try:
            base_features = extract_features(combined_report)
            model = train_dummy_model(base_features)  # Temporary inline training (replace with pre-trained)
            ml_result = classify_report(combined_report, model)
            combined_report["ml_result"] = ml_result
            print(f"🤖 ML Prediction: {ml_result['label']} ({ml_result['probability']:.2f})")
        except Exception as e:
            print(f"✗ ML classification failed: {e}")
            ml_result = {"error": str(e), "label": "unknown", "probability": 0.0}

        # --- Upload Report to Supabase ---
        try:
            supabase.storage.from_("scan-reports").upload(
                bucket_path,
                json.dumps(combined_report, indent=2).encode(),
                file_options={"content-type": "application/json"}
            )
            print(f"✓ Combined report saved: {bucket_path}")
        except Exception as e:
            print(f"✗ Failed to save combined report: {e}")

        # --- Return Final Response (summary only, including stage logs)---
        return {
            "filename": filename,
            "static_status": static_result.get("status") if static_result else "unknown",
            "static_stage_log": static_result.get("stage_log", []),
            "dynamic_status": dynamic_result.get("status") if dynamic_result else "unknown",
            "dynamic_stage_log": dynamic_result.get("stage_log", []),
            "bucket_path": bucket_path,
            "classification": ml_result.get("label", "unknown"),
            "malicious_probability": ml_result.get("probability", 0.0)
        }

    finally:
        try:
            os.remove(apk_path)
        except Exception:
            pass
