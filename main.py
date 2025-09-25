from fastapi import FastAPI, File, UploadFile, HTTPException
from supabase import create_client, Client
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import requests

# Load environment variables
load_dotenv(override=True)

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "").strip()
MOBSF_URL = os.getenv("MOBSF_URL", "http://127.0.0.1:8001/api/v1").strip()

if not SUPABASE_URL or not SUPABASE_KEY or not MOBSF_API_KEY:
    raise RuntimeError("Missing SUPABASE_URL, SUPABASE_KEY, or MOBSF_API_KEY in .env")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Pydantic model for logs
class LogEntry(BaseModel):
    source: str
    type: str
    severity: str
    message: str

app = FastAPI(title="Capstone Backend", description="Malicious APK Detector 🚀")

@app.get("/")
def root():
    return {"message": "Capstone Backend running 🚀"}

@app.post("/add-log")
def add_log(entry: LogEntry):
    data = entry.dict()
    resp = supabase.table("logs").insert(data).execute()
    if resp.get("error"):
        raise HTTPException(status_code=500, detail=f"Failed to add log: {resp['error']}")
    return {"status": "log added", "data": data}

@app.get("/get-logs")
def get_logs():
    resp = supabase.table("logs").select("*").execute()
    if resp.get("error"):
        raise HTTPException(status_code=500, detail=f"Failed to fetch logs: {resp['error']}")
    return {"logs": resp.data}

@app.post("/analyze-apk/")
async def analyze_apk(file: UploadFile = File(...)):
    try:
        # Upload APK to MobSF
        file_content = await file.read()
        files = {"file": (file.filename, file_content, "application/octet-stream")}
        headers = {"Authorization": MOBSF_API_KEY}
        upload_resp = requests.post(f"{MOBSF_URL}/upload", files=files, headers=headers)

        try:
            upload_json = upload_resp.json()
        except ValueError:
            raise HTTPException(status_code=500, detail=f"MobSF did not return valid JSON: {upload_resp.text}")

        if "hash" not in upload_json:
            raise HTTPException(status_code=500, detail=f"MobSF upload failed: {upload_json}")

        apk_hash = upload_json["hash"]

        # Scan APK
        scan_resp = requests.post(
            f"{MOBSF_URL}/scan",
            json={"hash": apk_hash},
            headers={"Authorization": MOBSF_API_KEY, "Content-Type": "application/json"}
        ).json()

        # Get report
        report_resp = requests.get(
            f"{MOBSF_URL}/report_json/{apk_hash}/",
            headers={"Authorization": MOBSF_API_KEY}
        ).json()

        # Extract findings
        keywords = ["debug", "root", "strandhogg", "vulnerable"]
        findings = []

        def walk(obj):
            if isinstance(obj, dict):
                for v in obj.values(): walk(v)
            elif isinstance(obj, list):
                for item in obj: walk(item)
            elif isinstance(obj, str):
                s = obj.lower()
                for kw in keywords:
                    if kw in s:
                        findings.append(obj)

        walk(report_resp)

        # Save log
        log_resp = supabase.table("logs").insert({
            "source": "MobSF",
            "type": "APK Scan",
            "severity": "Info",
            "message": f"Scanned {file.filename}"
        }).execute()

        # Save findings
        for f in findings:
            supabase.table("findings").insert({
                "apk_name": file.filename,
                "finding": f,
                "severity": "High" if "root" in f.lower() or "strandhogg" in f.lower() else "Medium"
            }).execute()

        return {"status": "success", "findings": findings}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"APK scan failed: {e}")
