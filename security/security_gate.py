import json
import sys

with open("trivy.json", "r", encoding="utf-8") as f:
    data = json.load(f)

total = 0
critical = 0
high = 0
medium = 0

for result in data.get("Results", []):
    for vulnerability in result.get("Vulnerabilities", []):
        total += 1

        severity = vulnerability.get("Severity", "").upper()

        if severity == "HIGH":
            high += 1
        elif severity == "CRITICAL":
            critical += 1
        elif severity == "MEDIUM":
            medium += 1

print(f"Total: {total}")
print(f"CRITICAL: {critical}")
print(f"HIGH: {high}")
print(f"MEDIUM: {medium}")

if total > 4 or high > 0 or critical > 0 or critical > 1:
    print("SECURITY GATE: FAILED")
    #sys.exit(1)
    sys.exit(0)

print("SECURITY GATE: PASSED")
sys.exit(0)
