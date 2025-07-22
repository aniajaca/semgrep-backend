### Example `/scan-code` Response

```json
{
  "status": "success",
  "language": "javascript",
  "findings": [],
  "riskScore": 0,
  "metadata": {
    "scanned_at": "2025-07-22T08:28:59.952Z",
    "code_length": 20,
    "semgrep_version": "1.127.1",
    "findings_count": 0,
    "performance": {
      "totalScanTime": "13374.37ms",
      "semgrepTime": "11587.43ms",
      "classificationTime": "0.09ms",
      "memoryUsed": "0MB",
      "totalMemory": "11MB",
      "peakMemory": "9MB"
    }
  },
  "riskAssessment": {
    "riskScore": 0,
    "riskLevel": "Minimal",
    /* …rest of the object… */
  }
}