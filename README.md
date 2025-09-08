## Prerequisites
- Windows 10/11 with **PowerShell**
- **Mendix Studio Pro 10.23.0**
- **Docker Desktop** (for SonarQube & OWASP ZAP containers)
- Chrome/Edge for manual checks and BugBug
- Do **not** commit secrets; use environment variables

---

## Quick Start (10 minutes)
1. **Run one app locally** (e.g., TaskTracker → *Run Locally*; note URL like `http://localhost:8082/`).
2. **SAST (Automated)** — scan with SonarQube; export screenshots + 3–5 bullet summary to `reports/<App>/SAST/`.
3. **DAST–Active (Automated)** — run ZAP full/active scan; save `zap-active-<app>.html` to `reports/<App>/DAST/`.
4. **DAST–Passive (Manual)** — browse and observe headers/cookies/routes; save screenshots + notes to `reports/<App>/DAST/passive/`.
5. **BugBug** — record RBAC/IDOR flows
6. Create `reports or input and output folder/<App>/SUMMARY.md` (use the template below) linking to your evidence.



## Run the Apps Locally
- Open `apps/<AppName>/` in Mendix Studio Pro **10.23.0** and **Run Locally**.  
- Typical ports: `8081`, `8082`, …  
- Use demo users if available (e.g., `MxAdmin/1` or role-based demo creds). If different, note them in `tests/<TOOL>/<App>/README.md`.

> If switching to **Production** security causes entity access errors, stay on **Demo/Prototype** for this artefact and document the constraint.



## SAST — Automated (SonarQube)
**Start SonarQube (Docker):**
```powershell
docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community
# After ~1–2 minutes open http://localhost:9000 and create a user token

