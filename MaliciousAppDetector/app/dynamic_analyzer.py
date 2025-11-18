import subprocess
import time
import os
from dotenv import load_dotenv

load_dotenv()


class DynamicAnalyzer:
    def __init__(self):
        # Lock to emulator-5554 to avoid multiple device conflicts
        self.device_id = "emulator-5554"
        self.emulator_name = os.getenv("EMULATOR_NAME", "MalwareTest_Safe")
        self.analysis_duration = int(os.getenv("DYNAMIC_DURATION", "60"))

    # -----------------------------
    # ✅ Universal ADB Runner
    # -----------------------------
    def adb_run(self, args, **kwargs):
        """Run ADB commands scoped to the emulator only."""
        cmd = ["adb", "-s", self.device_id] + args
        return subprocess.run(cmd, **kwargs)

    # -----------------------------
    # ✅ Sanity Checks
    # -----------------------------
    def check_adb_installed(self):
        try:
            subprocess.run(["adb", "version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def check_emulator_running(self):
        try:
            result = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
            return self.device_id in result.stdout
        except Exception:
            return False

    # -----------------------------
    # ✅ Start Emulator (if not running)
    # -----------------------------
    def start_emulator(self):
        if self.check_emulator_running():
            print(f"🟢 Emulator {self.device_id} already running.")
            return True

        print(f"🚀 Starting emulator: {self.emulator_name}")
        subprocess.Popen(
            ["emulator", "-avd", self.emulator_name, "-no-snapshot-load"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Give emulator enough time to boot
        print("⌛ Waiting for emulator to boot...")
        subprocess.run(["adb", "wait-for-device"], timeout=120)
        time.sleep(20)
        print("✅ Emulator ready.")
        return True

    # -----------------------------
    # ✅ Install APK
    # -----------------------------
    def install_apk(self, apk_path):
        print(f"📦 Installing APK on {self.device_id}: {apk_path}")
        result = self.adb_run(["install", "-r", apk_path],
                              capture_output=True, text=True, timeout=90)
        if result.returncode == 0:
            print("✓ APK installed successfully.")
            return True
        print(f"✗ APK installation failed: {result.stderr.strip()}")
        return False

    # -----------------------------
    # ✅ Extract Package Name
    # -----------------------------
    def get_package_name(self, apk_path):
        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=15
            )

            if result.returncode != 0 or not result.stdout:
                print(f"✗ aapt failed: {result.stderr}")
                return None

            for line in result.stdout.split("\n"):
                if line.startswith("package:"):
                    package = line.split("name='")[1].split("'")[0]
                    print(f"📦 Detected package name: {package}")
                    return package
        except FileNotFoundError:
            print("✗ aapt not found. Please add Android Build Tools to PATH.")
        except Exception as e:
            print(f"✗ Error extracting package name: {e}")
        return None

    # -----------------------------
    # ✅ Launch & Fuzz App
    # -----------------------------
    def launch_and_fuzz_app(self, package_name, event_count=300):
        print(f"🐒 Launching Monkey fuzz test for {package_name} ({event_count} events)")
        try:
            self.adb_run(["logcat", "-c"], timeout=15)  # Increased timeout
        except subprocess.TimeoutExpired:
            print("⚠️ logcat clear timeout ignored — continuing anyway.")

        result = self.adb_run([
            "shell", "monkey",
            "-p", package_name,
            "--ignore-crashes",
            "--ignore-timeouts",
            "--monitor-native-crashes",
            "-v", str(event_count)
        ], capture_output=True, text=True, timeout=120)
        print("✓ Fuzzing complete.")
        return result.returncode == 0

    # -----------------------------
    # ✅ Monitor Logs
    # -----------------------------
    def monitor_behavior(self, duration=None):
        duration = duration or self.analysis_duration
        print(f"⏱️ Monitoring app for {duration} seconds...")
        time.sleep(duration)

        try:
            result = self.adb_run(["logcat", "-d"],
                                  capture_output=True, text=True, encoding="utf-8", timeout=20)
            logs = result.stdout
            print(f"✓ Collected {len(logs)} log characters.")
            return logs
        except subprocess.TimeoutExpired:
            print("⚠️ logcat dump timed out — returning partial logs.")
            return ""
        except Exception as e:
            print(f"✗ Error collecting logs: {e}")
            return ""

    # -----------------------------
    # ✅ Analyze Logs
    # -----------------------------
    def analyze_logs(self, logs):
        print("🔍 Analyzing behavior patterns...")
        if not logs:
            print("⚠️ No logs captured.")
            return {}

        behavior = {
            "network_calls": logs.count("http://") + logs.count("https://"),
            "file_operations": logs.count("FileOutputStream") + logs.count("FileInputStream"),
            "sms_activity": logs.count("SMS") + logs.count("sendTextMessage"),
            "location_access": logs.count("LocationManager") + logs.count("getLastKnownLocation"),
            "camera_usage": logs.count("Camera") + logs.count("takePicture"),
            "contacts_access": logs.count("ContactsContract"),
            "phone_calls": logs.count("ACTION_CALL") + logs.count("TelephonyManager"),
            "permission_requests": logs.count("permission"),
            "crashes": logs.count("FATAL EXCEPTION"),
            "native_code": logs.count("JNI") + logs.count("native"),
            "crypto_operations": logs.count("Cipher") + logs.count("encrypt"),
            "database_operations": logs.count("SQLite") + logs.count("database"),
        }

        active = {k: v for k, v in behavior.items() if v > 0}
        print(f"✓ Behavior summary: {active}")
        return active

    # -----------------------------
    # ✅ Uninstall App
    # -----------------------------
    def uninstall_app(self, package_name):
        print(f"🧹 Uninstalling {package_name} from {self.device_id}")
        self.adb_run(["uninstall", package_name], capture_output=True, timeout=15)

    # -----------------------------
    # ✅ Full Dynamic Analysis
    # -----------------------------
    def analyze_apk(self, apk_path):
        print(f"🔬 Starting dynamic analysis for {os.path.basename(apk_path)}")

        if not self.check_adb_installed():
            return {"status": "failed", "error": "ADB not installed."}

        if not os.path.exists(apk_path):
            return {"status": "failed", "error": f"APK not found: {apk_path}"}

        # Ensure emulator is running
        if not self.check_emulator_running():
            print("⚠️ No emulator detected — starting now...")
            self.start_emulator()
            time.sleep(15)
        else:
            print(f"🟢 Using emulator: {self.device_id}")

        # Install APK
        if not self.install_apk(apk_path):
            return {"status": "failed", "error": "APK installation failed."}

        # Extract package
        package_name = self.get_package_name(apk_path)
        if not package_name:
            return {"status": "failed", "error": "Could not extract package name."}

        # Run fuzz + monitor
        self.launch_and_fuzz_app(package_name, event_count=300)
        logs = self.monitor_behavior()
        behavior = self.analyze_logs(logs)
        self.uninstall_app(package_name)

        print(f"✓ Dynamic analysis complete for {package_name}.")
        return {
            "status": "success",
            "package_name": package_name,
            "apk_file": os.path.basename(apk_path),
            "duration": self.analysis_duration,
            "behavior": behavior
        }


if __name__ == "__main__":
    analyzer = DynamicAnalyzer()
    import sys
    if len(sys.argv) > 1:
        result = analyzer.analyze_apk(sys.argv[1])
        print("\n=== FINAL RESULT ===")
        print(result)
    else:
        print("Usage: python dynamic_analyzer.py <apk_path>")
