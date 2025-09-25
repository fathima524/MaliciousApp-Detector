from fastapi import FastAPI, File, UploadFile
from supabase import create_client, Client
import requests
from pydantic import BaseModel

import os
from dotenv import load_dotenv

load_dotenv()  # loads .env file into environment variables

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY")
MOBSF_URL = os.getenv("MOBSF_URL", "http://127.0.0.1:8001/api/v1")

# optional simple check so you fail fast if a key is missing
if not SUPABASE_URL or not SUPABASE_KEY or not MOBSF_API_KEY:
    raise RuntimeError("Missing SUPABASE_URL, SUPABASE_KEY or MOBSF_API_KEY in environment (.env)")


class LogEntry(BaseModel):
    source: str
    type: str
    severity: str
    message: str

app = FastAPI()

# ✅ Root check
@app.get("/")
def root():
    return {"message": "Capstone Backend running 🚀"}

# ✅ Add log manually
@app.post("/add-log")
def add_log(entry: LogEntry):
    data = entry.dict()
    supabase.table("logs").insert(data).execute()
    return {"status": "log added", "data": data}

# ✅ Get logs
@app.get("/get-logs")
def get_logs():
    response = supabase.table("logs").select("*").execute()
    return {"logs": response.data}

# ✅ Analyze APK with MobSF
@app.post("/analyze-apk/")
async def analyze_apk(file: UploadFile = File(...)):
    try:
        files = {"file": (file.filename, await file.read(), "application/octet-stream")}
        headers = {"Authorization": MOBSF_API_KEY}

        # Step 1: Upload APK
        upload = requests.post(f"{MOBSF_URL}/upload", files=files, headers=headers).json()

        # Step 2: Scan APK
        scan = requests.post(f"{MOBSF_URL}/scan", json=upload, headers=headers).json()

        # Step 3: Extract important findings (simplified)
        findings = []
        keywords = ["debug", "root", "strandhogg", "vulnerable"]

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

        walk(scan)

        # Save logs + findings
        supabase.table("logs").insert({
            "source": "MobSF",
            "type": "APK Scan",
            "severity": "Info",
            "message": f"Scanned {file.filename}"
        }).execute()

        for f in findings:
            supabase.table("findings").insert({
                "apk_name": file.filename,
                "finding": f,
                "severity": "High" if "root" in f.lower() or "strandhogg" in f.lower() else "Medium"
            }).execute()

        return {"status": "success", "findings": findings}

    except Exception as e:
        return {"status": "error", "details": str(e)}

