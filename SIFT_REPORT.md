# SIFT Module Report for CyberGuard Pro

This document provides a comprehensive overview of the SIFT module contained
in the CyberGuard Pro project. It is intended to give context for further
research or development work.

---

## 📌 1.  What is SIFT?

> **SIFT** – _Security-Informed Functional Testing_ – is an AI-driven
> code-auditing component embedded in CyberGuard Pro. Its job is to ingest
> source code (primarily Python but other languages as well), reason about
> it, and surface:

- hallucinated or malicious imports (“slopsquatting”);
- logic gaps and unfinished handlers;
- injection and other security risks.

It operates **hybrid-AI/static-analysis** style: a lightweight static
pre-processing step augments and constrains reasoning performed by a large
language model.

---

## 🧱 2.  Core Components

### 2.1 `core/sift_engine.py`

This is the heart of the module.

- **Initialization**
  - Accepts an `SIFT_API_KEY` used to construct an `openai.OpenAI` client
    (via `base_url=https://api.longcat.chat/openai`).
  - Uses a fixed model ID (`LongCat-Flash-Thinking-2601`).

- **Language detection**
  - `detect_language()` uses [Pygments](https://pygments.org/) to guess the
    code’s lexer.
  - Returns `"Unknown"` on failure.

- **Registry verification** *(research feature)*
  - `_verify_imports_with_pypi()` extracts `import`/`from` names, filters
    standard-library modules, and queries PyPI.
  - Flags existence, 404 (hallucination), or network failures.
  - Text output is injected into the LLM prompt as “REAL-TIME REGISTRY
    CONTEXT.”

- **Analysis pipeline** (`analyze_code()`)
  - Detects language; if Python, runs registry verification.
  - Builds a **system prompt** instructing the model to:
    1. Detect hallucinated imports, logic gaps, injection risks.
    2. Use explicit chain-of-thought reasoning.
    3. Output **strict JSON** containing `analysis_steps`, numeric `score`,
       and a list of `vulnerabilities`.
  - Sends the prompt as an OpenAI chat completion.
  - Cleans up markdown formatting and attempts to parse JSON (with extra
    handling for backslashes in the `core/` copy).
  - Returns either parsed result or an error object.

> *Logging* is sprinkled throughout; errors don’t halt the host process.

### 2.2 `sift_reasoning_eval.py`

Auxiliary module for evaluating the quality and explainability of SIFT’s
output.

- **CoT prompt generator** (`generate_cot_prompt`)
  - Wraps a code snippet with instructions to trace data dependencies,
    control flow, and conclude with `VERDICT: vulnerable/clean`.

- **Monitorability metric** (`evaluate_monitorability`)
  - Heuristic “LLM-as-judge” that scores an explanation [0..1]:
    - rewards mentions of variable names
    - checks for keywords like *branch*, *dependency*, *control flow*.

- **`XAIEvaluator` class**
  - Used by benchmarks to compute:
    - `recovery_rate`: whether the predicted vulnerable line matches the
      true line.
    - `fidelity`: fraction of provided control-flow descriptions reflected in
      the explanation.

This file also contains a small demo when executed as `__main__`.

### 2.3 Benchmark and testing harness

Located at `tests/sift_benchmark_harness.py`.

- Loads a **CodeMirage** CSV dataset (paths under `data/sift/…`).
- Maintains SQLite table `benchmark_results` with columns for:
  - input code, ground truth, language
  - sift score, prediction object, issues list
  - processing time, error log, timestamps
- Schema migration logic handles legacy columns.
- `run_benchmark()` iterates dataset rows, calls
  `SiftEngine.analyze_code()`, and records results.
- Another script (`tests/backfill_evaluation_metadata.py`) interprets SIFT
  output to populate `ground_truth` and compute simple predictions.

> This harness evidences how SIFT is integrated into the project’s
> **evaluation pipeline**.

### 2.4 Support script (`verify_sift.py`)

Small convenience script to sanity‑check the engine:

- Tests `detect_language()` with sample Python/JS snippets.
- Notes that `analyze_code()` requires a real API key or a mocked client.

### 2.5 Architecture & Documentation

`SIFT_ARCHITECTURE.md` offers a narrative summary:

- **System boundaries** – SIFT sits inside CyberGuardPro, with inputs from
  code repos and outputs to vulnerability reports and annotated code.
- **Dual-agent design** – analysis engine + contextual validator
  communicating via encrypted channels.
- **CMMM level 4** – adaptive posture; feedback loops feed telemetry into
  learning routines (`ai/*` code).
- **Literature comparison** – contrasts SIFT with traditional SAST tools,
  highlighting AI augmentation.
- **Benchmarks and threats** – DARPA AIxCC 2023–2025 usage, attention to
  slopsquatting.

Several Markdown docs (e.g. `SIFT_CODE_AUDITOR_MODULE_REPORT.md` etc.) in
the repo may contain additional context.

---

## 🔗 Integration Points

- `core/api_bridge.py` initializes the `SiftEngine` if `SIFT_API_KEY` is
  present.  
- CLI helpers such as `benchmark_runner.py` and `verify_project.py`
  reference the engine.  
- The `.env.example` file suggests the key is stored in environment variables.

---

## 🔍 Security‑Relevant Features

| Feature | Purpose | Notes |
|---------|---------|-------|
| PyPI verification | Detects hallucinated/nonexistent packages | Can flag
supply‑chain typosquatting |
| Chain‑of‑thought prompts | Forces model to reason through control flow |
JSON output facilitates automated parsing |
| Score/Issues structure | Enables threshold‑based prediction | Benchmarks
use score < 70 or non‑empty issues as “vulnerable” |
| Logging & error handling | Ensures engine failures are captured but
non‑fatal | Useful for real‑time CI runs |

---

## 📂 Related Files & Locations

- `core/sift_engine.py` – main implementation  
- `sift_reasoning_eval.py` – explainability utilities  
- `tests/sift_benchmark_harness.py` – evaluation framework  
- `verify_sift.py` – quick validation script  
- `SIFT_ARCHITECTURE.md` – architecture document  
- `data/sift/` – datasets used by benchmarks  
- `.env.example` – environment variable hint  
- `tests/backfill_evaluation_metadata.py` – dataset ingestion logic

---

## 🔚 Wrap‑up

SIFT is a **specialized, AI‑powered code auditor** that combines classic
lexical/static analysis with large-language-model reasoning and registry
checks. Its modular design (engine + evaluation + benchmark harness) supports
integration into CI/CD pipelines and continuous benchmarking against
adversarial datasets.

Use this report as background for:

1. Enhancing the prompt templates.
2. Extending PyPI/registry checks to other ecosystems.
3. Integrating SIFT results into the broader CyberGuardPro dashboard or
   remediation workflows.

Happy researching!