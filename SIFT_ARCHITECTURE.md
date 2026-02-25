# SIFT Architecture and Context

## 1. System Security Plan (SSP)

**System Boundaries**

SIFT (Security-Informed Functional Testing) operates as an AI-driven, code-auditing module within the broader CyberGuardPro ecosystem. Its primary inputs are source code repositories (Python, configuration files, and auxiliary scripts) and development artifacts. Outputs include vulnerability reports, prioritized remediation suggestions, and annotated code with identified logic concerns. SIFT integrates with continuous integration/continuous deployment (CI/CD) pipelines and developer IDEs through API bridges (`core/api_bridge.py`).

**Architectural Model**

SIFT employs a **Dual-Agent architecture**. One agent functions as the *Analysis Engine*, performing static examination and model-driven reasoning; the second agent serves as the *Contextual Validator*, which refines results using runtime traces, threat intelligence, and developer feedback. Communication between agents is mediated through encrypted channels to preserve integrity and freshness of the analysis.

**Mitigation Maturity Model (CMMM) Mapping**

When evaluated against the Cybersecurity Mitigation Maturity Model (CMMM), SIFT corresponds to a **Level 4 (Adaptive)** posture. It not only detects known patterns but also adapts to emerging threats via continuous learning from internal telemetry (e.g., `tests/sift_benchmark_harness.py`) and external datasets (e.g., DARPA AIxCC challenges). Outputs are fed back into training loops (`ai/train_hids.py`, `ai/train_nids.py`) to refine detection capabilities.


## 2. Literature Comparison

### Static Application Security Testing (SAST)

Traditional SAST solutions analyze source code heuristically or via pattern matching to uncover insecure constructs such as SQL injections, buffer overflows, or improper input validation. Well-known tools include SonarQube, Fortify, and open-source linters. SAST excels at **syntactic** vulnerabilities but frequently omits **context-dependent logic errors** where the same code path is safe or unsafe depending on configuration, user role, or runtime state.

*Examples of SAST Limitations*:

- Data flow across multiple modules where the type or constraints change dynamically.
- Permission checks that hinge on runtime flags or external policy files.
- AI-specific vulnerabilities such as prompt injection or hallucination-triggering code paths.

### SIFT's Advantage

SIFT supplements static reasoning with AI-informed contextual analysis. By leveraging a RAG-like retrieval component combined with behavioral models (a dual-agent interplay), it identifies cases where security is contingent on non-local state. Its internal tests (`test_sift.py` in the repository) are constructed to capture such logic errors, ensuring coverage beyond what classical SAST reports.


## 3. Benchmarks and Emerging Threats

SIFT's evaluation framework incorporates the DARPA AI Cyber Challenge (AIxCC) benchmarks from **2023–2025**. These benchmarks provided adversarial code samples designed to evaluate AI-based defensive and offensive tools. By replaying challenges against the SIFT model, engineers continuously gauge performance improvements and identify blind spots, particularly in handling obfuscated or adversarially modified code.

A contemporary threat vector addressed by SIFT is **"slopsquatting"**—the phenomenon where AI models hallucinate malicious package names resembling legitimate libraries, often in software supply chains. Traditional static analyzers rarely flag such speculative references, whereas SIFT cross-validates package names against known repositories and the DARPA-provided dataset of deceptive packages, flagging hallucination-driven dependencies during training of `ai/nlp_model.py`.


## References

1. DARPA AI Cyber Challenge (AIxCC) 2023–2025 official reports and dataset repository.
2. OWASP Top 10: Application Security Risks.
3. Cybersecurity Mitigation Maturity Model (CMMM) documentation.
4. NIST SP 800-18: Guide for Developing Security Plans for Federal Information Systems.
5. Research literature on SAST vs AI-driven security assessments (e.g., Kaur & Williams, 2022; Ruiz et al., 2024).

---

*This document serves as a formal architectural summary and literature context for SIFT, suitable for inclusion in academic publications and internal security reviews.*
