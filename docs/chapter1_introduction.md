# Chapter 1: Introduction

## 1.1 Background and Motivation

Modern software systems are assembled faster than they can be securely reviewed. Continuous integration pipelines, open-source dependency reuse, and AI-assisted code generation have all increased the rate at which code enters production, while the supply of qualified security reviewers has not scaled at the same pace. Public vulnerability databases such as the National Vulnerability Database (NVD) continue to record tens of thousands of new Common Vulnerabilities and Exposures (CVEs) each year, and a large share of these originate from a recurring, well-documented set of weakness classes cataloged in the OWASP Top 10 and the MITRE Common Weakness Enumeration (CWE).

Static Application Security Testing (SAST) tools such as SonarQube, CodeQL, and Snyk Code remain the industry standard for automated code-level security review. However, recent empirical evidence shows these tools suffer from very high false-positive rates in practice — an industry study at Tencent measured false-positive rates in excess of 76–90% for certain bug classes on a production static analyzer, with developers spending 10–20 minutes manually triaging each alarm (arXiv:2601.18844). This "alert fatigue" causes real vulnerabilities to be lost in noise. At the same time, Large Language Models (LLMs) have shown strong contextual code-understanding ability but, used naively, tend to rely on superficial code patterns rather than the true root cause of a vulnerability — for example, the Vul-RAG study found plain LLMs achieve only 0.06–0.14 pair-wise accuracy when asked to distinguish a vulnerable function from its patched counterpart (arXiv:2406.11147). Retrieval-Augmented Generation (RAG), which grounds an LLM's reasoning in retrieved, verifiable knowledge rather than relying solely on its parametric memory, has emerged as the most promising way to combine the contextual strength of LLMs with the precision and explainability that security review demands.

## 1.2 Problem Statement

As software applications become more complex, ensuring code security has become a critical challenge. Traditional static analysis tools often generate false positives or provide limited, template-based explanations, making it difficult for developers to understand and fix security vulnerabilities. Purely LLM-based reviewers, on the other hand, are prone to hallucinated or superficial judgments when they are not grounded in an authoritative knowledge base. There is a need for an intelligent system that not only detects vulnerabilities in real-world GitHub repositories, but also explains them with reference to recognized security standards (OWASP Top 10, CWE), assigns a defensible severity level, and recommends a concrete, verifiable fix — all with minimal false positives and full traceability of *why* a piece of code was flagged.

## 1.3 Project Objectives

The objective of this project is to design and develop a web-based application that automatically analyzes public GitHub repositories for security vulnerabilities using a Retrieval-Augmented Generation pipeline. Specifically, the project aims to:

1. Build an ingestion pipeline that clones a submitted GitHub repository and parses its source code into logical, function/method/class-level chunks.
2. Generate semantic vector embeddings for each code chunk and store them in a vector database to support contextual retrieval within the same repository.
3. Construct a separate, curated security knowledge base by embedding OWASP Top 10 and CWE documentation, so that every detection can be grounded in an authoritative standard rather than model intuition alone.
4. Implement a RAG pipeline that retrieves both intra-repository code context and external security knowledge for each chunk, and passes this combined context to an LLM for vulnerability analysis.
5. Design a transparent, rule-based severity scoring module inspired by the Common Vulnerability Scoring System (CVSS), so severity is not decided solely by LLM judgment.
6. Generate AI-assisted, human-verifiable remediation suggestions with before/after code comparisons.
7. Present all findings through an interactive dashboard supporting search, filtering, and severity-based triage.

## 1.4 Scope

**In scope (Project I / current phase):** Requirement analysis, literature and comparative study of existing LLM/RAG-based vulnerability detection approaches, system architecture and module-level design, technology stack selection and justification, knowledge base design (OWASP Top 10 + CWE ingestion plan), severity scoring rubric design, and a preliminary/prototype-level work plan.

**Out of scope for the current phase (planned for Project II / future work):** Full multi-language production support, CI/CD and IDE plugin integration, pull-request-level automated review, and large-scale historical trend/compliance reporting. These are captured under Future Scope (Section 3.7) and will be pursued as the implementation matures.

The initial prototype will target a small set of widely used, well-documented languages (e.g., Python and JavaScript/TypeScript) before broadening language coverage, in order to keep the scope achievable within the semester timeline while still validating the core RAG-based detection approach end to end.

## 1.5 Expected Outcomes

- A working pipeline that ingests a GitHub repository URL and returns a structured, chunk-level security analysis.
- Demonstrable reduction in false positives relative to signature/rule-only static analysis, achieved through RAG grounding in OWASP/CWE knowledge (consistent with published results such as ZeroFalse's F1 of ~0.91–0.96 and the Tencent study's 94–98% false-positive elimination when LLMs are combined with static analysis context — arXiv:2510.02534, arXiv:2601.18844).
- Explainable, standards-referenced vulnerability reports (mapped to specific OWASP/CWE identifiers).
- A transparent, reproducible severity score per finding.
- AI-generated, developer-reviewable remediation code.
- An interactive dashboard usable by a developer with no prior security training.

## 1.6 Organisation of the Report

Chapter 2 reviews recent literature on LLM- and RAG-based vulnerability detection, false-positive reduction, automated severity scoring, and automated repair, and positions the proposed system relative to this body of work. Chapter 3 presents the proposed methodology, system architecture, module-level design, technology stack, and feasibility/risk/work-planning analysis.
