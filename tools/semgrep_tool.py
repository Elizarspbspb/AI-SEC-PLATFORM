import subprocess
import json

def normalize_semgrep_result(data):
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        finding = {
            "rule": item.get("check_id"),
            "file": item.get("path"),
            "line": item.get("start", {}).get("line"),
            "severity": extra.get("severity"),
            "message": extra.get("message"),
        }
        findings.append(finding)
    return findings
    
def run_semgrep(
        project_path,
        rules_path,
        threads=4
):
    command = [
        "semgrep",
        "scan",
        f"--config={rules_path}",
        "-j",
        str(threads),
        "-v",
        "--json",
        project_path
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )
    if result.returncode not in [0,1]:
        raise Exception(
            result.stderr
        )
    #print("[!!!]", result.stdout)
    #return json.loads(result.stdout)
    
    stdout = result.stdout
    semgrep_json = json.loads(stdout)
    clean_results = normalize_semgrep_result(semgrep_json)
    print("[!!!]", clean_results)
    return clean_results
