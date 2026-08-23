---
name: solve-ctf-web
description: Tool-first web CTF skill for baseline requests, response diffs, and service startup handoff. Use when the challenge is an HTTP service, local URL, or API surface and the agent should stay on structured request tools.
---

# Solve CTF Web

1. Call `ctf_tool_audit` when local capability state is unknown or stale. Use `ctf_start` when routing or ranked choices are useful; direct HTTP/browser tools remain callable when the endpoint and backend are already known.
2. Use `ctf_http_request` for the baseline request and response capture.
3. Use `ctf_http_diff` for one controlled variation at a time.
4. Use `mcp.chrome` when configured for tabs, DOM, JavaScript, console, network, cookies, and screenshots.
5. Use `ctf_web_browser_probe` as the local headless fallback when mcp-chrome is unavailable or only a deterministic DOM/screenshot is needed.
6. Use `ctf_web_capture_probe` when live HTTP(S) capture or replay is needed.
7. Use `mcp.tavily` for CVE, framework, dependency, and vulnerability reference lookup when needed.
8. Use `ctf_tool_setup` for mcp-chrome or mitmproxy setup; the human receives exact ordered operations and returns only logs, screenshots, or OCR text.
9. Use `ctf_human_request` when a local service, browser, or GUI must be started by the user and the response should be a log, screenshot, or OCR text.

## Tool Graph

```text
audit -> ctf_tool_audit -> ctf_start -> ctf_http_request
baseline vs variant -> ctf_http_diff
rendered page -> mcp.chrome -> ctf_web_browser_probe
live traffic -> ctf_web_capture_probe -> ctf_tool_setup(mitmproxy)
CVEs/frameworks -> mcp.tavily
service missing -> ctf_human_request
```

## Notes

- Keep headers, method, body, and URL explicit.
- Compare status, length, and body hash before writing any custom client.
- Prefer curl-backed requests and preserve the exact response preview.
