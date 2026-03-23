from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def run_poc(definition, execution_input: dict[str, Any]) -> dict[str, Any]:
    temp_input_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        ) as temp_file:
            json.dump(execution_input, temp_file, ensure_ascii=False)
            temp_input_path = Path(temp_file.name)

        completed = subprocess.run(
            [sys.executable, str(definition.entrypoint_path), "--input", str(temp_input_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        stdout_text = completed.stdout.strip()
        stderr_text = completed.stderr.strip()

        if completed.returncode != 0:
            return {
                "poc_name": definition.name,
                "status": "Error",
                "description": "PoC process exited with non-zero status.",
                "evidence": f"exit_code={completed.returncode}",
                "raw_output": stdout_text,
                "debug_log": stderr_text,
                "vulnerable": False,
            }

        try:
            result = json.loads(stdout_text)
        except json.JSONDecodeError:
            return {
                "poc_name": definition.name,
                "status": "Error",
                "description": "PoC stdout is not valid JSON.",
                "evidence": "JSON parsing failed",
                "raw_output": stdout_text,
                "debug_log": stderr_text,
                "vulnerable": False,
            }

        if stderr_text:
            result["debug_log"] = stderr_text

        if "poc_name" not in result:
            result["poc_name"] = definition.name

        return result

    except subprocess.TimeoutExpired:
        return {
            "poc_name": definition.name,
            "status": "Timeout",
            "description": "PoC execution timed out.",
            "evidence": "timeout=10s",
            "raw_output": "",
            "debug_log": "",
            "vulnerable": False,
        }

    except Exception as e:
        return {
            "poc_name": definition.name,
            "status": "Error",
            "description": "Unexpected runner error.",
            "evidence": str(e),
            "raw_output": "",
            "debug_log": "",
            "vulnerable": False,
        }

    finally:
        if temp_input_path and temp_input_path.exists():
            temp_input_path.unlink()