import json
from datetime import datetime

INPUT_LOG = "../raw_logs/syslog.txt"
OUTPUT_FILE = "../logs/filtered_events_syslog.json"

# признаки подозрительной активности
SUSPICIOUS_PATTERNS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "sudo",
    "root",
    "permission denied",
    "segmentation fault",
    "exploit",
    "malware",
    "privilege"
]

def analyze_log(filename):
    events = []
    with open(filename, "r", errors="ignore") as file:
        for line_number, line in enumerate(file, start=1):
            lower = line.lower()
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in lower:
                    events.append(
                        {
                            "timestamp":
                                datetime.now().isoformat(),
                            "line":
                                line_number,
                            "pattern":
                                pattern,
                            "event":
                                line.strip()
                        }
                    )
                    break
    return events

def save_events(events):
    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            events,
            file,
            indent=4,
            ensure_ascii=False
        )

if __name__ == "__main__":
    events = analyze_log(INPUT_LOG)
    save_events(events)
    print(f"[+] Found events: {len(events)}")
    print(f"[+] Saved: {OUTPUT_FILE}")
