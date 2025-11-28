# XSS Cookie Lab

A comprehensive, reproducible, and academically structured laboratory for studying Cross-Site Scripting (XSS), cookie exfiltration flows, contextual sanitization, and empirical mitigation evaluation. This repository provides a complete environment where researchers, students, security practitioners, and instructors can explore XSS in realistic settings, while also analyzing thousands of payloads through an automated experimental pipeline.

This README is intentionally extensive. It serves both as user documentation and as a conceptual guide explaining the entire architecture, dataset, methodology, and evaluation workflow that power this project.

---

# 1. Introduction

Cross-site scripting (XSS) remains one of the most persistent and impactful vulnerabilities in modern web applications. While documented for more than two decades, XSS continues to appear in production systems due to:

- Obfuscated payloads
- Polyglot variants
- Blind XSS scenarios
- Weak or inconsistent server-side output encoding
- Misaligned client-side sanitization
- Insufficient contextual awareness

The **XSS Cookie Lab** is designed as a controlled environment for understanding these challenges in depth. The project includes:

- A deliberately vulnerable **Flask application**
- Multiple XSS entry points
- A functioning **cookie theft mechanism**
- A **context-aware mitigator** with configurable security modes
- A **unified dataset of 15,351 payloads** from Kaggle and GitHub
- A set of **Jupyter notebooks** for preprocessing, unification, exploration, and evaluation
- A fully instrumented **API testing endpoint** for automated, reproducible experiments
- A complete methodology aligned with academic cybersecurity research

---

# 2. Project Objectives

This repository aims to:

### 1. Provide a reproducible laboratory for:
- Reflected XSS
- Stored XSS
- Blind XSS
- Cookie exfiltration
- Contextual sanitization

### 2. Enable empirical evaluation of mitigation techniques by:
- Executing more than 15k payloads automatically
- Tracking mitigation decisions (block/allow)
- Recording reasons, matches, and contexts
- Computing classical metrics: precision, recall, F1, FP rate, specificity, etc.

### 3. Offer an educational platform for:
- University cybersecurity courses
- Capture-the-flag (CTF) training
- Penetration testing demonstrations
- Research on pattern-based and contextual mitigators
- Data-driven security evaluation

### 4. Serve as the companion repository for an academic article titled:
**“Context-Based Evaluation of Cross-Site Scripting Mitigation in a Flask Security Laboratory.”**

---

# 3. High-Level Architecture

The architecture consists of four major components:

## 3.1 Flask Web Laboratory
Found under `src/app/`, it contains:

- **main.py** – entry point
- **routes.py** – all endpoints (search, comments, contact, admin views, API)
- **security.py** – context-aware mitigator
- **storage.py** – JSON-based persistence layer
- **templates/** – user interface, dual vulnerable/mitigated display
- **static/** – styling

## 3.2 Cookie Collector
Implements:

- `/steal?c=...` endpoint
- storage of stolen cookies (JSONL + logs)
- `/admin/cookies` visualization

## 3.3 Dataset and Notebooks
Located under `notebooks/`, they include:

- Raw datasets  
- Processed and unified datasets  
- EDA notebooks  
- API experiment executor  
- Analytical summaries and generated figures  

## 3.4 Automated Evaluation Endpoint
```
POST /api/test_payload
```
Accepts:

- payload: a string
- context: execution/rendering context (text, html, attribute)

Returns:

- sanitized output
- block/allow decision
- semantic category
- activated families
- list of internal reasons
- structural indicators
- current security mode

---

# 4. Repository Structure

```
xss-cookie/
├── notebooks/
│   ├── data_processed/
│   ├── results/
│   ├── *.ipynb
│   ├── pipeline.pdf
│   └── flows.pdf
│
├── src/
│   ├── app/
│   ├── data/
│   ├── logs/
│   ├── scripts/
│   ├── tests/
│   └── deployment/
│
├── requirements.txt
├── .gitignore
└── README.md
```

Each directory is explained in-depth in later sections.

---

# 5. Installation and Environment Setup

This laboratory runs on Python 3.10+.

## Step 1 — Clone the repository
```
git clone https://github.com/AndresJimw/xss-cookie
cd xss-cookie
```

## Step 2 — Create and activate a virtual environment
**Linux/macOS:**
```
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell:**
```
python -m venv .venv
.\.venv\Scripts\Activate
```

## Step 3 — Install dependencies
```
pip install -r requirements.txt
```

## Step 4 — Create a `.env` file
Create `.env` at the root:

```
SECRET_KEY=your-secret-key
SECURITY_MODE=off
```

Valid modes:
- `off`
- `log`
- `block`

---

# 6. Running the Laboratory

## Option 1 — Using helper scripts

### Linux/macOS:
```
cd src
chmod +x scripts/run_dev.sh
./scripts/run_dev.sh
```

### Windows:
```
cd src
scripts
un_dev.bat
```

## Option 2 — Manual execution:
```
cd src
python -m app.main
```

Then visit:
```
http://localhost:5000
```

---

# 7. Security Modes Explained

### 7.1 Mode: `off`
- Fully vulnerable
- Ideal for demonstrations and understanding raw XSS behavior

### 7.2 Mode: `log`
- Escapes user input based on minimal contextual rules
- Flags suspicious patterns
- Does not block

### 7.3 Mode: `block`
- Applies contextual sanitization
- Blocks suspicious content outright
- Returns a placeholder for blocked content

---

# 8. Laboratory Scenarios

Each scenario is rendered twice:

- vulnerable view
- mitigated view

This dual view allows direct comparison.

## 8.1 Reflected XSS — `/search`
Displays user-supplied `q` parameter.

## 8.2 Stored XSS — `/comments`
Persists entries and renders them for all users.

## 8.3 Blind XSS — `/contact → /admin/messages`
Executed only when the admin views stored messages.

## 8.4 Cookie theft — `/steal` & `/admin/cookies`
Payloads can call `/steal?c=...`.

---

# 9. The Context-Aware Mitigator (`security.py`)

The mitigator operates in two phases:

## 9.1 Input Analysis
- Lowercases input
- Scans for 80+ patterns
- Aggregates matches into groups:
  - script_tag  
  - event  
  - active_tag  
  - scheme  
  - meta_tag  
  - dom_sink  
  - neutral_polyglot  
  - etc.

## 9.2 Sanitization & Decision
- Applies escaping depending on context
- Counts matches to determine severity
- In block mode:
  - Blocks if suspicious
  - Returns placeholder
- Logs reasons and categories

---

# 10. The `/api/test_payload` Endpoint

Example request:

```
POST /api/test_payload
{
  "payload": "<svg onload=alert(1)>",
  "context": "html"
}
```

Example response:

```
{
  "blocked": true,
  "category": "event",
  "categories": ["active_tag", "event"],
  "reasons": [
    "group:active_tag", 
    "group:event",
    "pattern:<svg",
    "pattern:onload="
  ],
  "sanitized": "[blocked by simple context-based filter]"
}
```

Used extensively in the notebooks.

---

# 11. Dataset Description

The unified payload corpus includes:

- Total instances: **15,351**
- Sources:
  - Kaggle (10,835)
  - GitHub (4,516)

## Core variables:
- `Sentence_clean`
- `Label`
- `family_main`
- `families_str`
- `len_after_clean`
- `source`
- Structural flags:
  - `has_script_tag`
  - `has_event`
  - `has_js_uri`
  - `has_iframe`

---

# 12. Jupyter Notebook Workflow

Located in `notebooks/`.

### 12.1 Data exploration
- Kaggle EDA
- GitHub EDA

### 12.2 Dataset unification
- Cleaning
- Normalizing
- Category assignment

### 12.3 API experiments
- Automatic attacks
- Logging decisions
- Generating CSVs

### 12.4 Analysis
- Metrics by dataset
- Metrics by family
- Structural flag behavior
- Threshold sensitivity
- Length analysis
- FP/FN case studies

---

# 13. Summary of Empirical Findings

- Recall: **0.946–0.992**
- Precision: **~0.97–0.99**
- F1: **>0.96**

### Family-level highlights:
- Script, iframe, js_uri, and event families: nearly perfect recall
- Benign family: main source of FP/FN
- GitHub benign subset includes many ambiguous strings

### Threshold analysis:
- Raising match threshold reduces FP but harms recall

### Structural flags:
- When active → recall ≈ 1.0
- When absent → more ambiguous cases

---

# 14. Deployment (AWS EC2)

In `src/deployment/aws_setup.md`.

Includes steps for:

- EC2 setup
- Environment configuration
- Running in production mode
- Behavior under block mode

---

# 15. Testing

To run tests:

```
cd src
pytest -q
```

---

# 16. Limitations

- Dataset not representative of real traffic
- Rule-based approach not exhaustive
- Only XSS is modeled (no SQLi or CSRF)
- Lab is intentionally vulnerable; do not expose to the public internet

---

# 17. Academic Citation

If used in research:

Nieto, B. A. J. (2025). *XSS Cookie Lab: A Context-Based Evaluation Environment for Cross-Site Scripting Mitigation*. Yachay Tech University.

---

# 18. Conclusion

This repository provides a full-stack environment for studying XSS in a rigorous, empirical, and reproducible way. It bridges educational demonstration, research methodology, and automated evaluation in a single, coherent platform. The combination of a vulnerable application, contextual mitigation, and a large unified corpus allows users to understand both the mechanics of XSS and the practical trade-offs involved in designing real-world defenses.

