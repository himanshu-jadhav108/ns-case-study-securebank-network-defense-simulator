# Streamlit Community Cloud Deployment Guide

This guide details the step-by-step deployment procedure for the **SecureBank Network Defense Simulator** on **Streamlit Community Cloud** (<https://share.streamlit.io>).

---

## 1. Deployment Summary

| Property | Value | Notes |
|---|---|---|
| **Platform** | Streamlit Community Cloud | Free hosting tier on Linux containers |
| **Python Version** | Python 3.11 or 3.12 | Recommended: Python 3.12 (CPython) |
| **Application Entry Point** | `app.py` (or `securebank/app.py` if deployed from outer root) | Headless Streamlit application |
| **Primary Dependencies** | `streamlit>=1.35.0,<2.0.0`, `pandas>=2.0.0` | Minimal footprint, instant build |
| **Secrets / API Keys** | None Required | Zero external API calls, zero paid tokens |
| **Network & Privileges** | In-process simulation only | No raw sockets, packet capture, or root privileges needed |

---

## 2. Pre-Deployment Verification Checklist

Before pushing to GitHub, verify that all local checks pass:

- [x] **Project Virtual Environment:** Use Python 3.11 or 3.12 virtual environment (`.venv\Scripts\python.exe` or `source .venv/bin/activate`).
- [x] **Dependency Check:** Run `pip check` to ensure no conflicting dependencies.
- [x] **Automated Tests:** Run `pytest -v` (all 45 test cases must pass).
- [x] **Syntax & Compilation:** Run `python -m py_compile app.py`.
- [x] **Local Headless Run:** Run `python -m streamlit run app.py --server.headless true` and verify HTTP 200 response on `/_stcore/health`.
- [x] **Path Safety:** All imports and data files resolve relative to `Path(__file__).resolve().parent`.

---

## 3. Git Repository Preparation

Push the code to a GitHub repository:

```bash
# Navigate to the project directory
cd securebank

# Initialize git repository (if not already initialized)
git init

# Stage tracked files (.gitignore excludes .venv, caches, and test logs)
git add .

# Create initial commit
git commit -m "feat: SecureBank Network Defense Simulator production ready"

# Set default branch
git branch -M main

# Link to your GitHub remote
git remote add origin https://github.com/<your-username>/<your-repo-name>.git

# Push to GitHub
git push -u origin main
```

> **Security Note:** Ensure `.gitignore` ignores `.venv/`, `venv/`, `__pycache__/`, `.pytest_cache/`, and `.streamlit/secrets.toml`.

---

## 4. Deploying on Streamlit Community Cloud

1. **Sign In:**
   - Go to [share.streamlit.io](https://share.streamlit.io).
   - Sign in using your GitHub account that hosts the repository.

2. **Create New Application:**
   - Click **Create app** (or **Deploy an app**).
   - Choose **Deploy a public app from GitHub**.

3. **Repository Settings:**
   - **Repository:** `<your-username>/<your-repo-name>`
   - **Branch:** `main`
   - **Main file path:** `app.py` (if the repo root is the `securebank` folder) or `securebank/app.py` (if pushed from the parent folder).
   - **App URL:** (Optional) Customize the app subdomain (e.g. `securebank-simulator.streamlit.app`).

4. **Advanced Settings (Optional):**
   - Click **Advanced settings**.
   - **Python version:** Select **3.11** or **3.12**.
   - **Secrets:** Leave empty (the simulation requires no secrets or API keys).

5. **Deploy:**
   - Click **Deploy!**.
   - Community Cloud will install dependencies from `requirements.txt` and launch the app in under 60 seconds.

---

## 5. Community Cloud Architecture & Constraints

- **Execution Sandbox:** The application runs completely in-process using synthetic data structures (`dummy_accounts.json` and in-memory event generators).
- **Ephemeral Filesystem:** Uploaded CSVs in the *Before vs After* tab are kept in session memory (`BytesIO`) and do not require permanent disk persistence.
- **Resource Footprint:** Memory usage is under 150 MB and CPU utilization is minimal, well within Streamlit Community Cloud's 1 GB RAM allocation limit.
- **Local Lab Boundary:** The local dummy banking service (`local_lab/banking_service.py`) and loopback test harness are for local developer environments only; they are never invoked on Streamlit Community Cloud.

---

## 6. Troubleshooting Common Issues

| Symptom | Probable Cause | Resolution |
|---|---|---|
| `ModuleNotFoundError: No module named 'src'` | Working directory mismatch on Linux | `app.py` includes automatic `sys.path.insert(0, str(Path(__file__).resolve().parent))` to prevent import failures. |
| `FileNotFoundError: README.md` | Cloud working directory is not app directory | Resolved: `app.py` checks both `PROJECT_ROOT / "README.md"` and `Path("README.md")`. |
| App reloads unexpectedly | File watcher or memory spike | Configured `headless = true` and cached layer ablation (`@st.cache_data`) prevent excess computations. |
| Dependency install failure | Incompatible dependency pin | `requirements.txt` specifies tested version ranges (`streamlit>=1.35.0,<2.0.0` and `pandas>=2.0.0`). |

---

## 7. Official Documentation Reference

- Streamlit Community Cloud Deployment Docs: <https://docs.streamlit.io/deploy/streamlit-community-cloud>
- Streamlit Configuration Options: <https://docs.streamlit.io/develop/api-reference/configuration/config.toml>
