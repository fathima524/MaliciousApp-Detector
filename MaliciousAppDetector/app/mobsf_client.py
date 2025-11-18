import requests
import os
from dotenv import load_dotenv

# Load environment variables from .env file in the project root folder
dotenv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
load_dotenv(dotenv_path)

MOBSF_URL = os.getenv("MOBSF_URL", "http://127.0.0.1:8000")
API_KEY = os.getenv("MOBSF_API_KEY", "f1e2a9b4cf5d3e895437f8eda524b2733474fd7dcc0d0dab06637bb64c83e9ef")

def upload_apk_and_get_report(filename: str, file_content: bytes):
    headers = {"Authorization": API_KEY}
    files = {"file": (filename, file_content)}

    # Upload APK to MobSF
    upload_response = requests.post(f"{MOBSF_URL}/api/v1/upload", files=files, headers=headers)
    if upload_response.status_code != 200:
        return {"file_name": filename, "error": "Failed to upload to MobSF"}

    upload_data = upload_response.json()
    md5_hash = upload_data.get("hash")

    # Retrieve detailed report using hash
    report_response = requests.post(f"{MOBSF_URL}/api/v1/report_json", data={"hash": md5_hash}, headers=headers)
    if report_response.status_code != 200:
        return {"file_name": filename, "error": "Failed to retrieve report"}

    report = report_response.json()

    return {
        "file_name": upload_data.get("file_name"),
        "package_name": report.get("package_name"),
        "permissions": report.get("permissions"),
        "suspicious": report.get("suspicious"),
        "reason": report.get("reason"),
        "md5_hash": md5_hash,
        "summary_report": report
    }
