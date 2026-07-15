import subprocess
import json

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
    return json.loads(
        result.stdout
    )
