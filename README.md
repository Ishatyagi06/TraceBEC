# TraceBEC: Research-Oriented BEC Detection & Digital Email Forensics Platform

**TraceBEC** is a digital email forensics and Business Email Compromise (BEC) detection platform designed to investigate suspicious emails using linguistic analysis and structured digital forensic evidence. The project explores whether combining email-text classification with forensic indicators can improve BEC detection, particularly for previously unseen email campaigns.

---

## 1. Central Research Question & Research Objective

> **Central Research Question:** *Can combining linguistic and digital-forensic evidence improve BEC detection on previously unseen email campaigns compared with text-only approaches?*

### Research Motivation

Fraudulent email attacks continue to evolve, with attackers using increasingly varied language, impersonation strategies, and email structures. A model that performs well on familiar emails may not necessarily generalize to entirely new attack campaigns.

TraceBEC investigates this challenge through two complementary components:

- **Natural Language Processing (NLP):** Analyzes email text to identify linguistic patterns associated with suspicious messages.
- **Digital Email Forensics:** Examines available email headers and metadata to support investigation and risk assessment.

The research aims to evaluate whether combining these sources of evidence improves detection and generalization beyond familiar email templates.

### NLP Baseline Evaluation

The NLP experimentation notebook uses a dataset of **20,000 emails** and evaluates four baseline classifiers using TF-IDF-based text features.

| Model | Accuracy | Precision | Recall | F1 Score | Training Time (seconds) |
|---|---:|---:|---:|---:|---:|
| Linear SVM | 0.9868 | 0.9863 | 0.9867 | 0.9865 | 27.02 |
| Logistic Regression | 0.9824 | 0.9793 | 0.9850 | 0.9821 | 26.58 |
| Naive Bayes | 0.9674 | 0.9780 | 0.9549 | 0.9663 | 25.71 |
| Dummy Classifier | 0.5096 | 0.0000 | 0.0000 | 0.0000 | 0.01 |

### Key Observations

1. **Linear SVM:** Achieved the highest reported baseline F1-score of 0.9865.
2. **Logistic Regression:** Achieved an F1-score of 0.9821.
3. **Naive Bayes:** Achieved an F1-score of 0.9663.
4. **Dummy Classifier:** Provides a reference point for comparison.
5. **Unseen-Campaign Research Gap:** High baseline performance does not establish generalization to new BEC campaigns. This requires separate campaign-disjoint evaluation.

### NLP Research Pipeline

```text
Email Dataset (20,000 Emails)
             |
             v
Exploratory Data Analysis
             |
             v
       Text Preprocessing
             |
             v
     TF-IDF Feature Extraction
             |
             v
       Baseline Classifiers
             |
             v
     Performance Evaluation
             |
             v
 Future Campaign-Disjoint Testing
```

The final step represents the research objective and requires validation using suitable campaign-disjoint data.

---

## 2. Platform Architecture

```text
TraceBEC/
├── backend/
│   ├── app/
│   │   ├── api/v1/             # /analyze, /datasets, /experiments, /investigations
│   │   ├── forensics/          # Safe RFC 5322 parser, 32-dim feature extractor, leakage auditor
│   │   ├── models/             # NLP classifiers, forensic baseline, fusion model, calibrator
│   │   ├── schemas/            # Strongly-typed Pydantic contracts
│   │   └── main.py             # FastAPI entrypoint
│   ├── tests/                  # Automated pytest test suites
│   └── requirements.txt
├── frontend/                   # React + TypeScript + Vite security dashboard
│   ├── src/
│   │   ├── components/         # TriageBadge, EvidenceView, ResearchLabView,
│   │   │                       # DatasetProfilerView, SettingsView
│   │   └── services/api.ts     # Typed API Client
│   └── dist/                   # Production compiled bundle
├── data/samples/               # Verified sample .eml files
└── research/                   # Reproducible benchmark logs
```

### Architecture Overview

- **Backend:** FastAPI service for email analysis, model inference, forensic feature extraction, dataset profiling, and investigation management.
- **NLP Module:** Processes email text using TF-IDF features and trained baseline classifiers.
- **Forensic Module:** Extracts structured evidence from available email headers and metadata.
- **Fusion Module:** Provides the architectural location for combining NLP predictions with structured forensic features, subject to implementation and empirical validation.
- **Frontend:** React, TypeScript, and Vite dashboard for displaying classifications, evidence, and research results.

---

## 3. Quick Start Guide

### 3.1 Start the FastAPI Backend Server

Run the following commands from the repository root in PowerShell:

```powershell
$env:PYTHONPATH='backend'
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- **API Documentation:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health

Ensure the virtual environment and required dependencies are installed before starting the server.

### 3.2 Launch the Security Web Dashboard

Open a separate terminal and run:

```bash
cd frontend
npm run dev
```

Open http://localhost:5173 in your browser.

---

## 4. Digital Forensic Safeguards & Privacy Contracts

### 4.1 Explicit Unavailable Evidence

The system distinguishes between missing evidence and failed authentication.

- Missing authentication information must not automatically be treated as failed SPF or DKIM verification.
- Missing or stripped transit headers should be disclosed as **UNAVAILABLE EVIDENCE**.
- Conclusions should be limited to the evidence actually available to the investigator.

### 4.2 Out-of-Band Defensive Actions

High-risk and review-level assessments provide actionable verification recommendations, including:

- Verifying unusual payment or bank-account changes through a known telephone number or trusted directory.
- Applying dual authorization for sensitive financial transactions.
- Independently verifying urgent requests involving credentials, payments, or confidential information.

### 4.3 Configurable Retention

The platform specification supports two operating modes:

- **Investigation Mode:** Local audit logging and investigation management, with deletion endpoints such as `DELETE /api/v1/investigations/{id}`.
- **Ephemeral Mode:** In-memory analysis with immediate discard after processing.

Actual retention and deletion guarantees depend on the implemented backend and must be verified through testing.

### 4.4 Zero Untrusted Execution

- Email content is treated as untrusted input.
- Scripts and iframes must not be executed during email analysis.
- Attachments are inspected through safe structural or metadata parsing rather than execution.
- Suspicious URLs and embedded content must not be opened automatically during analysis.

---

## 5. Research Methodology

TraceBEC separates text-based classification from forensic evidence analysis to investigate the contribution of each modality.

### Stage 1: Text-Based Classification

Email text is preprocessed and transformed into TF-IDF features. Linear SVM, Logistic Regression, Naive Bayes, and Dummy Classifier are evaluated using accuracy, precision, recall, F1-score, and training time.

### Stage 2: Digital Email Forensics

The forensic subsystem parses available email headers and metadata to extract structured features. Missing, unavailable, and failed evidence remain distinct in the investigation output.

### Stage 3: Comparative Evaluation

The NLP baseline can be compared with a forensic-only model and, where implemented, a fusion model combining text representations with forensic features.

The comparison should use consistent data partitions and appropriate evaluation metrics to minimize data leakage.

### Stage 4: Unseen-Campaign Evaluation

The central research direction is to test whether the system detects BEC emails from campaigns excluded from training.

The evaluation protocol should:

1. Identify or construct defensible campaign groups.
2. Exclude all emails from a held-out campaign from training.
3. Train on the remaining campaign groups.
4. Evaluate on the held-out campaign.
5. Compare text-only, forensic-only, and fusion approaches where available.
6. Report per-campaign results and limitations.

If campaign labels are unavailable, potential groups may be explored using sender information, domains, timestamps, and content similarity. These inferred groups must be validated before being treated as genuine campaigns.

---

## 6. Research Scope & Limitations

TraceBEC focuses on BEC detection, explainable email investigation, and the evaluation of model generalization beyond familiar email patterns.

The current NLP notebook reports strong baseline classification results on its 20,000-email dataset. However, these scores alone do not establish:

- Successful generalization to unseen BEC campaigns.
- The ability to discover hidden relationships between different campaigns.
- Improved performance from multimodal fusion.
- Reliable probability calibration on external data.
- Real-world production performance or latency.

These claims require further experiments using suitable held-out campaign data, independently validated forensic evidence, and reproducible evaluation protocols.

The research contribution is centered on **empirically evaluating whether linguistic evidence and digital email forensics can improve BEC detection under unseen-campaign conditions**.

---

## 7. Expected Research Contribution

TraceBEC aims to provide:

- A reproducible NLP baseline for email classification.
- Structured forensic evidence to support email investigations.
- A platform for comparing text-based and forensic-based detection.
- An evaluation framework for campaign-disjoint testing.
- Evidence-based analysis of the benefits and limitations of combining linguistic and forensic information.

The ultimate objective is to investigate whether TraceBEC can move beyond recognizing familiar malicious email patterns and provide more reliable detection when confronted with previously unseen BEC campaigns.
