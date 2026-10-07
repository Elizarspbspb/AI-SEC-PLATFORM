# запуск - PYTHONPATH=../DAST python dast_gate_fuzzer.py
import sys
import os
import json
import atheris
from unittest.mock import patch, mock_open

TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "DAST"))

if TARGET_DIR not in sys.path:
    sys.path.insert(0, TARGET_DIR)

from dast_gate import analyze_nuclei, analyze_zap

RESULT_FILE = "fuzz_results.json"

def save_result(function_name, exception, payload):
    if os.path.exists(RESULT_FILE):
        try:
            with open(RESULT_FILE, "r", encoding="utf-8") as f:
                results = json.load(f)
            if not isinstance(results, list):
                results = []
        except (json.JSONDecodeError, OSError):
            results = []
    else:
        results = []
    error_type = type(exception).__name__

    # Не сохраняем один и тот же тип ошибки
    for result in results:
        if (result["function"] == function_name and result["error_type"] == error_type):
            return
    result = {
        "function": function_name,
        "error_type": error_type,
        "error": str(exception),
        "payload": payload
    }

    results.append(result)

    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)

def TestOneInput(data):
    # Atheris передаёт bytes и преобразует их в строку для подменённого файла.
    try:
        fuzz_string = data.decode("utf-8",errors="ignore")
    except Exception:
        return
        
    # Функиця analyze_nuclei
    with patch("dast_gate.open",mock_open(read_data=fuzz_string)):
        try:
            analyze_nuclei("fake_nuclei_report.json")
        except Exception as e:
            # Обычные ошибки не считаем интересными для фаззинга.
            if (isinstance(e, json.JSONDecodeError) or type(e).__name__ == "ParseError"):
                pass
            else:
                print()
                print("!" * 50)
                print("[!] Найдено исключение в analyze_nuclei")
                print(f"[!] Тип: {type(e).__name__}")
                print(f"[!] Ошибка: {e}")
                print("[!] Payload:")
                print(fuzz_string)
                print("!" * 50)
                print()

                save_result("analyze_nuclei", e, fuzz_string)
                
    # Функиця analyze_nuclei
    with patch("dast_gate.open",mock_open(read_data=fuzz_string)):
        try:
            analyze_zap("fake_zap_report.json")
        except Exception as e:
            # Обычные ошибки не считаем интересными для фаззинга.
            if (isinstance(e, json.JSONDecodeError) or type(e).__name__ == "ParseError"):
                pass
            else:
                print()
                print("!" * 50)
                print("[!] Найдено исключение в analyze_zap")
                print(f"[!] Тип: {type(e).__name__}")
                print(f"[!] Ошибка: {e}")
                print("[!] Payload:")
                print(fuzz_string)
                print("!" * 50)
                print()
                save_result("analyze_zap",e,fuzz_string)

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv,TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
