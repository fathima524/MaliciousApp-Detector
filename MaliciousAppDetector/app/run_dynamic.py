# app/run_dynamic.py

from dynamic_analyzer import DynamicAnalyzer
import sys

if __name__ == "__main__":
    apk_path = sys.argv[1]
    analyzer = DynamicAnalyzer()
    result = analyzer.analyze_apk(apk_path)
    print(result)
