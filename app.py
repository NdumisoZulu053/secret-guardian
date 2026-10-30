import json
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from pydantic import BaseModel
from typing import List, Optional

from engine.scanner import SecretScanner

app = FastAPI(
    title="Code Secret Guardian API",
    description="Modular security API to detect hardcoded passwords, keys, and DB credentials.",
    version="1.0.0"
)

# Load Rules on startup
RULES_FILE = Path("config/rules.json")
if RULES_FILE.exists():
    with open(RULES_FILE, "r") as f:
        rules_data = json.load(f)
else:
    rules_data = []

scanner = SecretScanner(rules=rules_data)

class CodeScanRequest(BaseModel):
    filename: Optional[str] = "input_code.py"
    code: str

class ScanResult(BaseModel):
    is_secure: bool
    total_findings: int
    findings: List[dict]

@app.post("/api/v1/scan/text", response_model=ScanResult)
async def scan_code_text(payload: CodeScanRequest):
    """Scan raw code passed as a string payload."""
    findings = scanner.scan_content(payload.code, filename=payload.filename)
    return ScanResult(
        is_secure=len(findings) == 0,
        total_findings=len(findings),
        findings=findings
    )

@app.post("/api/v1/scan/file", response_model=ScanResult)
async def scan_code_file(file: UploadFile = File(...)):
    """Scan an uploaded code file before saving or pushing."""
    try:
        content = (await file.read()).decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Only UTF-8 encoded plain text files are supported.")

    findings = scanner.scan_content(content, filename=file.filename)
    return ScanResult(
        is_secure=len(findings) == 0,
        total_findings=len(findings),
        findings=findings
    )

@app.get("/health")
def health_check():
    return {"status": "healthy", "loaded_rules": len(rules_data)}