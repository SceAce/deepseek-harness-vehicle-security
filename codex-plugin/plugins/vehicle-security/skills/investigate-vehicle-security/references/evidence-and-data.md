# Evidence and Data Management

Create one case directory per objective:

```text
<case-id>/
  case.json
  raw/
  working/
  evidence/
  scripts/
  reports/
```

- `raw/`: immutable attachments and captures, or a manifest pointing to immutable source paths.
- `working/`: extracted filesystems, converted captures, IDBs, patched copies, decoded data, replay-ready inputs.
- `evidence/`: raw command/MCP/debugger outputs, screenshots, logs, packet exports, and hashes.
- `scripts/`: rerunnable parsers, validators, IDAPython, Frida, debugger, and reproduction helpers.
- `reports/`: snapshots, findings, and final report.

Name evidence as `<ID>_<UTC>_<tool>_<description>.<ext>`. Store large raw output on disk and put only its path, hash, summary, and relevant offsets in `case.json`.

Use this minimum state shape:

```json
{
  "schemaVersion": "1.0",
  "caseId": "vehicle-IDENTIFIER",
  "objective": "",
  "phase": "P0",
  "selectedLane": "unknown",
  "inputs": [],
  "environment": [],
  "evidence": [],
  "conclusions": [],
  "hypotheses": [],
  "validations": [],
  "findings": [],
  "decisions": [],
  "nextActions": []
}
```

Each evidence record must include an ID, type, source/tool, summary, path, timestamp, hash when applicable, and confidence. Each hypothesis must include evidence IDs, competing explanations, validation ID, status, and confidence. Each validation must include exact input, expected positive and negative signals, observed result, raw evidence paths, and stop condition.

Do not overwrite previous observations when interpretation changes. Append a decision that supersedes the earlier conclusion and links both evidence sets.
