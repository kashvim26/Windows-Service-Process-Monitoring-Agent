# Deployment and Git publishing

## 1. Run locally first

Use Python 3.11 or newer on Windows. Open PowerShell in the project root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set `API_TOKEN` to a long unique value. A simple way to create one is:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(40))"
```

Run the web app:

```powershell
uvicorn app.main:app --reload
```

Visit `http://127.0.0.1:8000`. In a second PowerShell window, install collector dependencies and submit a snapshot:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r agent/requirements.txt
$env:MONITOR_API_URL = 'http://127.0.0.1:8000'
$env:MONITOR_API_TOKEN = 'paste-the-same-token-from-.env'
python agent/collector.py --once
```

The dashboard should show the host and any generated findings. Collect locally without sending data using `python agent/collector.py --once --local-only --output .\work\snapshot.json`.

## 2. Run the collector on a schedule

Create a Windows Task Scheduler task on the monitored endpoint:

1. Create a task named `Sentinel Windows Monitor`.
2. Choose a trigger such as every 5 minutes (or a cadence approved by your operations team).
3. Set the action to `python.exe`; arguments: `C:\path\to\project\agent\collector.py --once`.
4. Set **Start in** to the project root. Set `MONITOR_API_URL` and `MONITOR_API_TOKEN` as machine or task environment variables, or use a protected wrapper script. Avoid putting secrets directly in task arguments.
5. Choose the least privilege account that can read the telemetry you need. Elevation improves service visibility; protect the API token and review the collector before running it elevated.

For a continuous foreground run, `python agent/collector.py --interval 300` repeats every five minutes. Task Scheduler is easier to supervise and restart.

## 3. Push to GitHub

Create an empty repository on GitHub (do not initialize it with a README if you already have this one). In PowerShell at the project root:

```powershell
git init
git add .
git status
git commit -m "Build Sentinel Windows monitoring agent"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/sentinel-windows-monitor.git
git push -u origin main
```

Replace `YOUR-USERNAME` and the repository name. GitHub may open a browser sign-in flow. If Git is not installed, install Git for Windows first. Before `git add`, confirm `.env`, databases, snapshots, and logs are not included; `.gitignore` excludes these by default. Your public portfolio link will be `https://github.com/YOUR-USERNAME/sentinel-windows-monitor`.

## 4. Deploy the dashboard/API on Render

1. Sign in to Render and connect the GitHub repository.
2. Choose **New + → Blueprint**, select the repository, and apply its `render.yaml` blueprint.
3. The blueprint creates a Python web service with a generated `API_TOKEN`, a health check, and a persistent disk mounted at `/var/data` for SQLite.
4. Deploy and wait for the service to become live. The public URL will look like `https://sentinel-windows-monitor.onrender.com`. Open it; `/api/health` should return `{"status":"ok","version":"1.0.0"}`.
5. Copy the generated `API_TOKEN` from the service's environment settings. Treat it as a password. Configure the Windows machine:

```powershell
$env:MONITOR_API_URL = 'https://YOUR-SERVICE.onrender.com'
$env:MONITOR_API_TOKEN = 'paste-the-generated-token'
python agent/collector.py --once
```

Then refresh the site. Set the collector variables in a protected deployment mechanism on the endpoint, not in the repository. The bundled disk option is intended for a paid Render web service; Render documents persistent disks as a paid feature and notes that disk-backed services run as a single instance. If using a no-cost ephemeral service, use managed persistent storage before relying on collected history. Check current plan pricing before creating resources.

## 5. Make the portfolio link useful

- Keep the GitHub repository public if you want reviewers to see the code.
- Add a short repository description and topics such as `windows-security`, `blue-team`, `fastapi`, `endpoint-monitoring`.
- In GitHub's About section, add the live Render URL as the website.
- Add screenshots of the dashboard populated with test or sanitized data to the README.
- Never publish real hostnames, usernames, process paths, API tokens, or collected snapshots.

## Troubleshooting

- **401 from `/api/snapshots`:** the collector token does not match the service's `API_TOKEN`.
- **503 from `/api/snapshots`:** configure a non-empty `API_TOKEN` on the server.
- **No services in snapshot:** run on Windows and confirm PowerShell/CIM is available. Elevated rights can improve access.
- **Dashboard shows zero hosts:** verify the collector posted successfully and `MONITOR_API_URL` has no `/api` suffix.
- **Data disappeared after deploy:** ensure SQLite's `DATABASE_PATH` is under the attached persistent disk mount.

## Operational boundary

The collector sends process metadata (names, paths, usernames) and service configuration to the API. Review this telemetry for privacy before enabling it on other people's devices. Use only on systems you own or are authorized to monitor. This starter does not validate executable signatures or inspect process memory.
