---
name: solve-ctf-web
description: Tool-first web CTF skill for baseline requests, response diffs, and service startup handoff. Use when the challenge is an HTTP service, local URL, or API surface and the agent should stay on structured request tools.
---

# Solve CTF Web

1. Call `ctf_start` first when only the prompt or a URL is known.
2. Use `ctf_http_request` for the baseline request and response capture.
3. Use `ctf_http_diff` for one controlled variation at a time.
4. Use `ctf_human_request` when a local service, browser, or GUI must be started by the user and the response should be a log, screenshot, or OCR text.

## Tool Graph

```text
url -> ctf_start -> ctf_http_request
baseline vs variant -> ctf_http_diff
service missing -> ctf_human_request
prompt-only -> ctf_tool_audit -> ctf_http_request
```

## Notes

- Keep headers, method, body, and URL explicit.
- Compare status, length, and body hash before writing any custom client.
- Prefer curl-backed requests and preserve the exact response preview.
