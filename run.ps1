# Start the Secure SQL Agent on Windows.
#
# Usage:
#     .\run.ps1
#     .\run.ps1 -local
#     .\run.ps1 -local -db adventureworks
#
# Without -local, starts the FastAPI API on 127.0.0.1:8000.
# With -local, starts the interactive command-line REPL.
#
# -db picks a database from config/settings/databases.yaml, which holds each
# database's connection and points at its security and semantic config.
# Without -db: the SQLAGENT_DATABASE user variable (setx SQLAGENT_DATABASE
# adventureworks) if set, otherwise the file's default.
#
# All other settings are in config/settings/*.yaml (llm.yaml for the Ollama
# host and model, api.yaml for the API limits, ...). This script no longer
# sets them; an environment variable such as OLLAMA_MODEL or
# DEMO_AGENT_TIMEOUT still overrides the file for a one-off run, and
# startup prints which ones are in effect.
#
# Secrets are NOT stored in this file. Set them once as Windows user
# environment variables (then open a new PowerShell window):
#     setx PG_PASSWORD "your-sqlagent_ro-password"
#
# ASSUMES OLLAMA IS ALREADY RUNNING at the host in config/settings/llm.yaml
# (http://localhost:11434: the Windows tray app, or an 'ollama serve' you
# started yourself). This script does not start Ollama or set its server
# options. Settings such as OLLAMA_NUM_PARALLEL and OLLAMA_MAX_LOADED_MODELS
# are read only when the Ollama server starts, so setting them here would
# have no effect.
#
# To start Ollama with this project's server settings, use
# run_with_ollama.ps1 instead. Note that it shuts down any Ollama that is
# already running.

param(
    [switch]$local,
    [string]$db
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# --- Ollama: same machine, so no tunnel and no auth needed --------------
# llm.yaml names OLLAMA_USERNAME / OLLAMA_PASSWORD for a tunnelled Ollama;
# clear them so no credentials are sent to the local one.
Remove-Item Env:OLLAMA_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:OLLAMA_PASSWORD -ErrorAction SilentlyContinue

# --- Database: chosen by name, details in config/settings/databases.yaml --
# Set from -db or the user variable every time, so a value left in this
# window by an earlier run can't select the wrong database.
if ($db) {
    $env:SQLAGENT_DATABASE = $db
} else {
    $env:SQLAGENT_DATABASE = [Environment]::GetEnvironmentVariable("SQLAGENT_DATABASE", "User")
}
# Host, port, database and user come from config/settings/databases.yaml; clear
# any left over from older versions of this script so nothing suggests
# otherwise.
Remove-Item Env:PG_HOST, Env:PG_PORT, Env:PG_DATABASE, Env:PG_USER -ErrorAction SilentlyContinue
# The password is never in the YAML: databases.yaml names the variable
# (password_env: PG_PASSWORD). Lookup, in order:
#   1. already set in this window ($env:PG_PASSWORD = "...")
#   2. saved with setx; read straight from the Windows user settings, so
#      it works even in a window opened before setx was run
#   3. otherwise ask for it (input is hidden, used for this run only)
if (-not $env:PG_PASSWORD) {
    $env:PG_PASSWORD = [Environment]::GetEnvironmentVariable("PG_PASSWORD", "User")
}
if (-not $env:PG_PASSWORD) {
    $secure = Read-Host "Postgres password (PG_PASSWORD)" -AsSecureString
    $env:PG_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if (-not $env:PG_PASSWORD) {
    throw "No Postgres password given."
}

# --- API --------------------------------------------------------------------
# Limits, timeouts and proxy hops are in config/settings/api.yaml.
#
# CORS origins: put them in api.yaml (allowed_origins), or keep them
# per-machine as a user variable, which overrides the file:
#     setx DEMO_ALLOWED_ORIGIN "https://example.com,https://www.example.com"
# Read straight from the Windows user settings so it also works in a window
# opened before setx was run.
if (-not $env:DEMO_ALLOWED_ORIGIN) {
    $env:DEMO_ALLOWED_ORIGIN = [Environment]::GetEnvironmentVariable("DEMO_ALLOWED_ORIGIN", "User")
}

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