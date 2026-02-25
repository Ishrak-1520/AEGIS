# SIFT Code Auditor -- Architecture and Design Diagrams

All diagrams are written in Mermaid syntax for direct use in research papers, Markdown renderers, or export to SVG/PNG via mermaid.live.

---

## 1. System Architecture (High-Level)

```mermaid
graph TB
    subgraph "Presentation Layer"
        UI["SiftScanner.jsx<br/>(React + Framer Motion)"]
    end

    subgraph "Bridge Layer"
        API["AegisAPI.sift_analyze_code()<br/>(pywebview JS-API Bridge)"]
    end

    subgraph "SIFT Engine Core"
        SE["SiftEngine"]
        LD["Language Detector<br/>(Pygments)"]
        RV["Registry Verifier"]
        RD["ReDoS Scanner<br/>(Static Regex Analysis)"]
        LLM["LLM Auditor<br/>(OpenAI-compatible API)"]
        FR["Fix Recognizer<br/>(Diff-based Patch Review)"]
    end

    subgraph "External Services"
        PYPI["PyPI Registry<br/>pypi.org/pypi/PKG/json"]
        NPM["npm Registry<br/>registry.npmjs.org/PKG"]
        AI["LLM Endpoint<br/>(LongCat API)"]
    end

    UI -->|"window.pywebview.api"| API
    API --> SE
    SE --> LD
    SE --> RV
    SE --> RD
    SE --> LLM
    SE --> FR
    RV -->|"HTTP GET"| PYPI
    RV -->|"HTTP GET"| NPM
    LLM -->|"chat.completions.create()"| AI
    FR -->|"chat.completions.create()"| AI

    style UI fill:#0d1b2a,stroke:#00f0ff,color:#fff
    style SE fill:#1b2a3d,stroke:#00f0ff,color:#fff
    style AI fill:#2d1b3d,stroke:#a855f7,color:#fff
    style PYPI fill:#1b3d2a,stroke:#22c55e,color:#fff
    style NPM fill:#1b3d2a,stroke:#22c55e,color:#fff
```

---

## 2. Analysis Pipeline (Data Flow)

```mermaid
flowchart LR
    A["Raw Source Code<br/>+ Filename"] --> B["Language Detection<br/>(Pygments guess_lexer)"]
    B --> C{"Language?"}
    C -->|"Python"| D["PyPI Registry<br/>Verification"]
    C -->|"JS / TS"| E["npm Registry<br/>Verification"]
    C -->|"Other"| F["Skip Registry"]
    D --> G["ReDoS Pattern<br/>Scanner"]
    E --> G
    F --> G
    G --> H["Compose LLM Prompt<br/>(System + User msg)"]
    H --> I["LLM Inference<br/>(JSON mode)"]
    I --> J["Parse & Sanitize<br/>JSON Response"]
    J --> K["Merge regex_warnings<br/>into result"]
    K --> L["Final Audit Report<br/>{score, vulnerabilities,<br/>analysis_steps,<br/>suggested_fix}"]

    style A fill:#0d1b2a,stroke:#00f0ff,color:#fff
    style I fill:#2d1b3d,stroke:#a855f7,color:#fff
    style L fill:#1b3d2a,stroke:#22c55e,color:#fff
```

---

## 3. Sequence Diagram (End-to-End Audit Flow)

```mermaid
sequenceDiagram
    actor User
    participant UI as SiftScanner.jsx
    participant Bridge as AegisAPI
    participant Engine as SiftEngine
    participant Pygments as Pygments Lexer
    participant Registry as PyPI / npm
    participant LLM as LLM API

    User->>UI: Paste code + click "Analyze"
    UI->>Bridge: sift_analyze_code(code, language)
    Bridge->>Engine: analyze_code(code, filename=language)

    Engine->>Pygments: guess_lexer(code)
    Pygments-->>Engine: language name

    alt Python detected
        Engine->>Registry: GET pypi.org/pypi/{pkg}/json
        Registry-->>Engine: 200 OK / 404 Not Found
    else JS/TS detected
        Engine->>Registry: GET registry.npmjs.org/{pkg}
        Registry-->>Engine: 200 OK / 404 Not Found
    end

    Engine->>Engine: detect_regex_patterns(code)

    Engine->>LLM: chat.completions.create(system_prompt, user_msg)
    LLM-->>Engine: JSON {score, vulnerabilities, analysis_steps, suggested_fix}

    Engine->>Engine: sanitize JSON + merge regex_warnings
    Engine-->>Bridge: audit result dict
    Bridge-->>UI: result
    UI->>UI: Map keys (vulnerabilities->issues)
    UI-->>User: Render score, summary, vulnerability cards + suggested fixes
```

---

## 4. Class Diagram (SiftEngine)

```mermaid
classDiagram
    class SiftEngine {
        -client: OpenAI
        -model: str
        +__init__(api_key: str)
        +detect_language(code_content: str) str
        +analyze_code(code_content: str, filename: str) dict
        +analyze_fixed_code(vulnerable_code: str, fixed_code: str, filename: str) dict
        +compute_diff_summary(vulnerable_code: str, fixed_code: str) str
        +detect_regex_patterns(code: str) list
        -_verify_imports_with_pypi(code_content: str) str
        -_verify_imports_with_npm(code_content: str) str
    }

    class AegisAPI {
        -sift_engine: SiftEngine
        +sift_detect_language(code_content: str) str
        +sift_analyze_code(code_content: str, language: str) dict
    }

    class SiftScanner {
        -code: string
        -language: string
        -analysisResult: object
        +handleAnalyze() void
        +detectLanguage(content) void
        +handleFileUpload(event) void
        +copyToClipboard(text, index) void
    }

    AegisAPI --> SiftEngine : delegates to
    SiftScanner --> AegisAPI : "window.pywebview.api"
```

---

## 5. Hybrid Analysis Strategy

```mermaid
graph TB
    subgraph "Static Analysis"
        S1["Regex Pattern Scanner<br/>(ReDoS / CWE-730)"]
        S2["Import Extraction<br/>(regex-based)"]
        S3["Registry Verification<br/>(PyPI + npm HTTP)"]
    end

    subgraph "AI Analysis"
        A1["LLM Security Audit<br/>(Injection, Logic, Hallucination)"]
        A2["LLM Fix Generation<br/>(suggested_fix per vuln)"]
    end

    subgraph "Fusion"
        F1["Merge static warnings<br/>into LLM result"]
        F2["Final Scored Report"]
    end

    S1 --> F1
    S2 --> S3
    S3 --> A1
    A1 --> A2
    A2 --> F1
    F1 --> F2

    style S1 fill:#1b3d2a,stroke:#22c55e,color:#fff
    style S2 fill:#1b3d2a,stroke:#22c55e,color:#fff
    style S3 fill:#1b3d2a,stroke:#22c55e,color:#fff
    style A1 fill:#2d1b3d,stroke:#a855f7,color:#fff
    style A2 fill:#2d1b3d,stroke:#a855f7,color:#fff
    style F2 fill:#0d1b2a,stroke:#00f0ff,color:#fff
```

---

## 6. Fix-Recognition Pipeline (Patch Review)

```mermaid
flowchart LR
    V["Vulnerable Code"] --> D["compute_diff_summary()<br/>(difflib.unified_diff)"]
    FX["Fixed Code"] --> D
    D --> P["Compose Fix-Review<br/>System Prompt"]
    P --> LLM["LLM Inference"]
    LLM --> R["Parse Result"]
    R --> OUT["Output:<br/>fix_recognized: bool<br/>fix_explanation: str<br/>score: 0-100<br/>vulnerabilities: list"]

    style V fill:#3d1b1b,stroke:#ef4444,color:#fff
    style FX fill:#1b3d2a,stroke:#22c55e,color:#fff
    style LLM fill:#2d1b3d,stroke:#a855f7,color:#fff
    style OUT fill:#0d1b2a,stroke:#00f0ff,color:#fff
```

---

## 7. Slopsquatting Detection Flow

```mermaid
flowchart TB
    CODE["Source Code"] --> EXT["Extract Imports<br/>(regex)"]
    EXT --> FILT["Filter Out<br/>Standard Library"]

    FILT --> Q{"Language?"}
    Q -->|"Python"| PYPI["GET pypi.org/pypi/PKG/json"]
    Q -->|"JS/TS"| NPM["GET registry.npmjs.org/PKG"]

    PYPI --> R1{"HTTP Status?"}
    NPM --> R2{"HTTP Status?"}

    R1 -->|"200"| VER1["VERIFIED<br/>Package exists"]
    R1 -->|"404"| HAL1["CRITICAL<br/>Hallucinated import"]
    R1 -->|"Other"| WARN1["WARNING<br/>Could not verify"]

    R2 -->|"200"| VER2["VERIFIED"]
    R2 -->|"404"| HAL2["CRITICAL<br/>Hallucinated import"]
    R2 -->|"Other"| WARN2["WARNING"]

    HAL1 --> CTX["Inject into LLM<br/>REGISTRY CONTEXT"]
    HAL2 --> CTX
    VER1 --> CTX
    VER2 --> CTX

    style HAL1 fill:#3d1b1b,stroke:#ef4444,color:#fff
    style HAL2 fill:#3d1b1b,stroke:#ef4444,color:#fff
    style VER1 fill:#1b3d2a,stroke:#22c55e,color:#fff
    style VER2 fill:#1b3d2a,stroke:#22c55e,color:#fff
```

---

## 8. SIFT Methodology (Research Paper)

```mermaid
flowchart TD
    subgraph "Phase 1: Input Acquisition"
        IN1["User pastes source code\nor uploads file"]
        IN2["Filename / extension\nextracted"]
    end

    subgraph "Phase 2: Language-Aware Preprocessing"
        LP1["Pygments lexical analysis\n(guess_lexer)"]
        LP2{"Detected\nLanguage"}
        LP3["Map to registry\nendpoint"]
    end

    subgraph "Phase 3: Static Analysis (Deterministic)"
        SA1["Regex-based import\nextraction"]
        SA2["Real-time registry\nverification\n(PyPI / npm HTTP)"]
        SA3["ReDoS pattern\ndetection\n(CWE-730)"]
        SA4["Classify each import:\nVERIFIED | NOT FOUND\n| UNKNOWN"]
    end

    subgraph "Phase 4: AI-Driven Analysis (Non-Deterministic)"
        AI1["Construct composite\nLLM prompt"]
        AI2["Inject static context:\n- Registry results\n- Regex warnings"]
        AI3["LLM inference\n(JSON-mode,\nstructured output)"]
        AI4["Vulnerability\nclassification:\nSecurity | Logic |\nHallucination"]
        AI5["Remediation\ngeneration\n(suggested_fix\nper vulnerability)"]
        AI6["Security scoring\n(0-100 scale,\n100 = safe)"]
    end

    subgraph "Phase 5: Report Synthesis"
        RS1["Sanitize and parse\nLLM JSON response"]
        RS2["Merge static\nReDoS warnings"]
        RS3["Final structured\naudit report"]
        RS4["Render to user:\nScore + Summary +\nVulnerability cards +\nSuggested fixes"]
    end

    IN1 --> LP1
    IN2 --> LP1
    LP1 --> LP2
    LP2 -->|"Python"| LP3
    LP2 -->|"JS / TS"| LP3
    LP2 -->|"Other"| SA3
    LP3 --> SA1
    SA1 --> SA2
    SA2 --> SA4
    SA4 --> AI2
    SA3 --> AI2
    AI2 --> AI1
    AI1 --> AI3
    AI3 --> AI4
    AI4 --> AI5
    AI5 --> AI6
    AI6 --> RS1
    RS1 --> RS2
    RS2 --> RS3
    RS3 --> RS4

    style IN1 fill:#0d1b2a,stroke:#00f0ff,color:#fff
    style LP1 fill:#1a2740,stroke:#3b82f6,color:#fff
    style LP2 fill:#1a2740,stroke:#3b82f6,color:#fff
    style SA1 fill:#1b3d2a,stroke:#22c55e,color:#fff
    style SA2 fill:#1b3d2a,stroke:#22c55e,color:#fff
    style SA3 fill:#1b3d2a,stroke:#22c55e,color:#fff
    style SA4 fill:#1b3d2a,stroke:#22c55e,color:#fff
    style AI1 fill:#2d1b3d,stroke:#a855f7,color:#fff
    style AI2 fill:#2d1b3d,stroke:#a855f7,color:#fff
    style AI3 fill:#2d1b3d,stroke:#a855f7,color:#fff
    style AI4 fill:#2d1b3d,stroke:#a855f7,color:#fff
    style AI5 fill:#2d1b3d,stroke:#a855f7,color:#fff
    style AI6 fill:#2d1b3d,stroke:#a855f7,color:#fff
    style RS3 fill:#0d1b2a,stroke:#f59e0b,color:#fff
    style RS4 fill:#0d1b2a,stroke:#f59e0b,color:#fff
```

---

> **Rendering**: Paste any diagram block into [mermaid.live](https://mermaid.live) to get an SVG/PNG export for your paper.
