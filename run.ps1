# Start the Secure SQL Agent on Windows.
#
# Usage:
#     .\run.ps1
#     .\run.ps1 -local
#
# Without -local, starts the FastAPI API on 127.0.0.1:8000.
# With -local, starts the interactive command-line REPL.
#
# Secrets are NOT stored in this file. Set them once as Windows user
# environment variables (then open a new PowerShell window):
#     setx PG_PASSWORD "your-sqlagent_ro-password"
#
# ASSUMES OLLAMA IS ALREADY RUNNING on http://localhost:11434 (e.g. the
# Windows tray app, or an 'ollama serve' you started yourself). This script
# does not start Ollama or set its server options. Settings such as
# OLLAMA_NUM_PARALLEL and OLLAMA_MAX_LOADED_MODELS are read only when the
# Ollama server starts, so setting them here would have no effect.
# (OLLAMA_HOST and OLLAMA_MODEL below are different: they tell the agent
# where to find Ollama and which model to use.)
#
# To start Ollama with this project's server settings, use
# run_with_ollama.ps1 instead. Note that it shuts down any Ollama that is
# already running.

param(
    [switch]$local
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# --- Ollama: same machine, so no tunnel and no auth needed --------------
$env:OLLAMA_HOST  = "http://localhost:11434"
$env:OLLAMA_MODEL = "qwen3-coder"
Remove-Item Env:OLLAMA_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:OLLAMA_PASSWORD -ErrorAction SilentlyContinue

# --- Postgres: local, read-only role (see WINDOWS-SETUP.md) --------------
$env:PG_HOST     = "localhost"
$env:PG_PORT     = "5432"
$env:PG_DATABASE = "northwind"
$env:PG_USER     = "sqlagent_ro"
# Password lookup, in order:
#   1. already set in this window ($env:PG_PASSWORD = "...")
#   2. saved with setx; read straight from the Windows user settings, so
#      it works even in a window opened before setx was run
#   3. otherwise ask for it (input is hidden, used for this run only)
if (-not $env:PG_PASSWORD) {
    $env:PG_PASSWORD = [Environment]::GetEnvironmentVariable("PG_PASSWORD", "User")
}
if (-not $env:PG_PASSWORD) {
    $secure = Read-Host "Password for Postgres user sqlagent_ro" -AsSecureString
    $env:PG_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if (-not $env:PG_PASSWORD) {
    throw "No Postgres password given."
}

# --- API limits ------------------------------------------------------------
$env:DEMO_AGENT_TIMEOUT = "120"
$env:DEMO_MAX_SLOT_HOLD = "150"

# The page is served from longbrothers.net but the API is on the ngrok
# domain, so the browser needs CORS permission for the site's origin.
$env:DEMO_ALLOWED_ORIGIN = "https://longbrothers.net,https://www.longbrothers.net"

# ngrok is the one proxy in front of the API and adds X-Forwarded-For.
$env:DEMO_TRUSTED_PROXY_HOPS = "1"

# Windows consoles default to a legacy code page; without this, printing a
# result such as "Folk och fä HB" can crash the request.
$env:PYTHONUTF8 = "1"

# --- Start ---------------------------------------------------------------

if ($local) {
    Write-Host "Starting Secure SQL Agent REPL..."
    & .\.venv\Scripts\python.exe main.py
}
else {
    Write-Host "Starting Secure SQL Agent API on http://127.0.0.1:8000..."
    & .\.venv\Scripts\python.exe -m uvicorn api:app --host 127.0.0.1 --port 8000 --workers 1
}
