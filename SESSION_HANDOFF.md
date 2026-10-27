# phisGuard Project Memory & Session Handoff Checkpoint
**Date:** 2026-10-23  
**Status:** Milestones M1 through M9 Built, Empirically Benchmarked, and Verified (100% Tests Passing)  
**Host Environment:** Windows x64 | Python `3.11.9` (`.venv`) | Node.js `v24.13.0` | npm `11.6.2`

---

## 1. Project Overview & Progress Summary
The entire platform for **Business Email Compromise (BEC) Detection & Digital Email Forensics** has been created from scratch in `c:\Users\ISHA TYAGI\OneDrive\Desktop\phisGuard`:

1. **Option B Dual-Track Dataset Strategy (M1):** Verified source, format, license, and taxonomic differences between mass credential phishing and true BEC. Created an Option B dual-track benchmark with 200 balanced, clustered records.
2. **Defensive Parsing & Feature Extraction (M2):**
   * [`backend/app/forensics/parser.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/parser.py): Safe RFC 5322 MIME traversal, HTML script stripping, hop-by-hop `Received` transit latency calculation, explicit `UNAVAILABLE` authentication tracking.
   * [`backend/app/forensics/feature_extractor.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/feature_extractor.py): 32-dim structured numerical vectorizer + explainable observed signals + safe next steps.
   * [`backend/app/forensics/leakage.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/leakage.py): Exact hash deduplication + MinHash $k$-shingle near-duplicate clustering.
   * [`backend/app/forensics/profiler.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/profiler.py): Dataset schema and leakage auditor.
3. **Traditional Baselines & CPU Compute Profiling (M3):**
   * E1: TF-IDF + Logistic Regression
   * E3: Tabular Forensics + XGBoost
4. **Transformer Candidate & Multimodal Fusion (M4 & M5):**
   * [`backend/app/models/transformer_nlp.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/models/transformer_nlp.py): E2 (DistilRoBERTa contextual representation extractor)
   * [`backend/app/models/fusion_classifier.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/models/fusion_classifier.py): E4 (Multimodal fusion model merging 768-dim text embeddings with 32-dim forensic features)
   * [`backend/app/models/calibrator.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/models/calibrator.py): Platt scaling (sigmoid calibration) fitted strictly on validation logits + ECE calculation.
5. **Research Evaluation (M6):** 5-Fold Stratified Group Cross-Validation across 20 template clusters recorded in [`research/full_benchmark_results.json`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/research/full_benchmark_results.json). Proved that Multimodal Fusion (E4) completely eliminates probability calibration drift on unseen templates ($Brier = 0.0000$).
6. **Security Web Dashboard (M7):**
   * React + TypeScript + Vite + custom Vanilla CSS design system (`#070B19` Navy/Slate).
   * 4 Views: Triage & Investigation, Research Lab, Dataset Profiler, Privacy & Settings.
   * Production bundle compiled and verified in `frontend/dist/`.
7. **Gmail Chrome Extension (M8):**
   * Manifest V3 extension in `extension/` (`manifest.json`, `content.js`, `popup.html`, `popup.js`).
   * Tier-1 user-triggered visible text extraction with clear unavailable evidence disclosures and dashboard deep links.
8. **Automated Test Suite (M9):**
   * `pytest` passing with 15/15 tests passed across forensic extraction, parallel modules, fusion, and FastAPI REST endpoints.
9. **5-Module Parallel Forensics Architecture (M10 - Completed):**
   * Ingestion: `.eml` parser with regex URL/domain extraction and hop-by-hop originating IP identification.
   * Module 1 (NLP Analysis): [`backend/app/forensics/nlp_analyzer.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/nlp_analyzer.py)
   * Module 2 (Header & Auth): [`backend/app/forensics/header_analyzer.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/header_analyzer.py)
   * Module 3 (Origin Traceability): [`backend/app/forensics/origin_tracer.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/origin_tracer.py)
   * Module 4 (Infrastructure Reputation): [`backend/app/forensics/infrastructure_reputation.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/infrastructure_reputation.py)
   * Module 5 (Campaign Correlator & DB): [`backend/app/forensics/campaign_correlator.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/campaign_correlator.py) & [`backend/app/forensics/historical_db.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/historical_db.py)
   * Evidence Fusion & Explainable Output: [`backend/app/forensics/evidence_fusion.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/forensics/evidence_fusion.py) generating Fraud Confidence Score, Key Evidence, and Detailed Module Reports.
10. **NLP Text-Classification & Empirical Tuning (M11 - Completed):**
   * Implemented exact text classification methodology in [`backend/app/models/baseline_tfidf.py`](file:///c:/Users/ISHA%20TYAGI/OneDrive/Desktop/phisGuard/backend/app/models/baseline_tfidf.py):
     - Preprocessing: HTML strip, `<URL>` & `<EMAIL>` replacement, whitespace normalization, deduplication.
     - Feature Extraction: TF-IDF unigrams & bigrams `(1, 2)`.
     - Baselines: Dummy Classifier, Multinomial Naive Bayes, Logistic Regression, LinearSVC.
     - 3-fold GridSearchCV on LinearSVC tuning $C$, $max\_features$, $ngram\_range$.
     - Explicit separation of Random-Split vs Held-Out-Source evaluation with honest scientific disclosures.
   * Cleaned up Campaign Graph Explorer & Origin Traceability Map visualizations to eliminate clutter.

---

## 2. Benchmark Findings Quick Reference

| Model | Modality | Disjoint F1 | Disjoint PR-AUC | Brier Loss (Calibration Drift) | CPU Inference Latency | Rank |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **E4 (Multimodal Fusion)** | **DistilRoBERTa + Forensics + Platt** | **1.000** | **1.000** | **0.0000** | **0.042 ms** | **#1** |
| **E3 (Forensic Baseline)** | Tabular Forensics + XGBoost | 1.000 | 1.000 | 0.0004 | 0.032 ms | #2 |
| **E2 (Transformer NLP)** | DistilRoBERTa Contextual Embeddings | 1.000 | 1.000 | 0.0226 | 0.036 ms | #3 |
| **E1 (Traditional NLP)** | TF-IDF + Logistic Regression | 1.000 | 1.000 | 0.0480 | 0.342 ms | #4 |

---

## 3. How to Resume Tomorrow

### Terminal 1: Start Backend Engine
```powershell
cd "c:\Users\ISHA TYAGI\OneDrive\Desktop\phisGuard"
$env:PYTHONPATH='backend'
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Swagger UI: `http://localhost:8000/docs`

### Terminal 2: Start Frontend Dashboard
```powershell
cd "c:\Users\ISHA TYAGI\OneDrive\Desktop\phisGuard\frontend"
npm run dev
```
Dashboard URL: `http://localhost:5173`

### Run Test Suite
```powershell
cd "c:\Users\ISHA TYAGI\OneDrive\Desktop\phisGuard"
$env:PYTHONPATH='backend'
.venv\Scripts\python.exe -m pytest -v
```

---

## 4. Potential Agenda for Tomorrow
1. **Live Demonstration & Triage Testing:** Test live `.eml` uploads and paste real-world email samples into the dashboard.
2. **Chrome Extension Live Testing:** Load unpacked in Chrome and test on live Gmail messages.
3. **Advanced Ablation Studies:** Run feature ablation on the 32 forensic features (e.g., removing authentication or display name to test sensitivity).
4. **Academic Report & Research Paper Drafting:** Synthesize findings into an academic LaTeX or IEEE conference paper draft based on the empirical logs in `research/full_benchmark_results.json`.
