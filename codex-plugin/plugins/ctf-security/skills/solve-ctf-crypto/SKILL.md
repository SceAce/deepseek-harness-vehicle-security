---
name: solve-ctf-crypto
description: Tool-first cryptography CTF skill for encoding triage, integer arithmetic, algebra, finite fields, elliptic curves, and constraint solving.
---

# Solve CTF Crypto

除工具名、命令、路径、代码和原始日志外，使用中文交流。所有 Python 命令必须使用 `/home/source/tools/PyVenv/CTF/bin/python`。

1. 使用 `ctf_tool_audit` 检查 Sage、PARI/GP、固定 Python 和已安装求解模块；能力状态已知时可以直接选择后端。
2. 先用 `ctf_crypto_probe` 识别 hex、base64、binary-ascii、熵、hash 和简单 XOR 候选。
3. 需要 Sage 特有能力时使用 `ctf_sage_exec`，例如有限域、椭圆曲线、符号代数和 Sage 数论对象。
4. 需要快速整数分解、离散对数或 PARI/GP 数论函数时使用 `ctf_gp_exec`。
5. Sage/GP 不可用但固定 Python 模块足够时，使用 `ctf_python_exec` 搭配 Z3、SymPy、gmpy2 或 PyCryptodome。
6. 只有在这些工具留下明确缺口后，才编写临时求解脚本。
7. 缺少 Sage 或 PARI/GP 时调用 `ctf_tool_setup`，人类只返回安装日志、截图或 OCR 文本。

## 工具图

```text
challenge text/file -> ctf_crypto_probe -> ctf_sage_exec
                                      -> ctf_gp_exec
                                      -> ctf_python_exec
missing Sage/GP -> ctf_tool_setup -> ctf_tool_audit -> selected crypto tool
```

## 选择原则

- 有限域、椭圆曲线、代数结构、Sage 专用对象：优先 Sage。
- 大整数分解、离散对数、PARI/GP 数论函数：优先 GP。
- 约束求解、常见密码算法、快速大整数和数据处理：优先固定 CTF Python。
- 每次记录后端路径、版本、精确参数、原始输出和可复现的中间结果。
