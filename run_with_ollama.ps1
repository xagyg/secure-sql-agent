<#
.SYNOPSIS
    Restarts the Ollama server with this project's settings, then starts the agent via run.ps1.

.DESCRIPTION
    Ollama reads server settings such as OLLAMA_NUM_PARALLEL and OLLAMA_MAX_LOADED_MODELS
    from its environment ONLY when the server starts. Setting them in an already-running
    session has no effect on a server that is already up.

    This script therefore:
      1. STOPS ANY RUNNING OLLAMA PROCESS, including the Windows tray app ("ollama app")
         and any existing "ollama serve". Any other program using Ollama at the time
         will lose its connection and any loaded models will be unloaded.
      2. Sets the Ollama server environment variables for this process only.
         (Your user/system environment variables are NOT changed.)
      3. Starts "ollama serve" in the background with those settings, logging to
         .\logs\ollama-serve.log.
      4. Waits until the Ollama API responds on http://localhost:11434.
      5. Runs .\run.ps1 (the API by default, or the REPL with -local).

    The Ollama server started here keeps running after this script exits.
    To go back to normal, stop it (e.g. Get-Process ollama | Stop-Process) and
    start the Ollama tray app again.

    If you'd rather manage Ollama yourself, use run.ps1 directly instead; it assumes
    Ollama is already running.

.PARAMETER NumParallel
    OLLAMA_NUM_PARALLEL: how many requests each loaded model serves concurrently.
    Default 1. Keep DEMO_MAX_CONCURRENCY in step with it (see README).

.PARAMETER MaxLoadedModels
    OLLAMA_MAX_LOADED_MODELS: how many models may be held in memory at once.

.PARAMETER KeepAlive
    OLLAMA_KEEP_ALIVE: how long an idle model stays loaded (e.g. "5m", "1h").
    Default "-1" keeps it loaded permanently, so no visitor waits for it to load.

.EXAMPLE
    .\run_with_ollama.ps1

.EXAMPLE
    .\run_with_ollama.ps1 -NumParallel 2 -KeepAlive 1h

.EXAMPLE
    .\run_with_ollama.ps1 -local
    Starts the command-line REPL instead of the API (passed on to run.ps1).
#>

[CmdletBinding()]
param(
    [int]    $NumParallel     = 1,
    [int]    $MaxLoadedModels = 1,
    [string] $KeepAlive       = "-1",
    [int]    $StartupTimeoutSeconds = 30,
    [switch] $local
)

$ErrorActionPreference = "Stop"
$OllamaUrl = "http://localhost:11434"

# --- Check Ollama is installed ---------------------------------------------------
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Error "The 'ollama' command was not found on PATH. Install Ollama from https://ollama.com and try again."
}

# --- 1. Stop any running Ollama (tray app and server) ----------------------------
$running = Get-Process | Where-Object { $_.Name -like "ollama*" }
if ($running) {
    Write-Host "Stopping running Ollama processes: $($running.Name -join ', ')" -ForegroundColor Yellow
    $running | Stop-Process -Force
    Start-Sleep -Seconds 2   # give Windows time to release port 11434
} else {
    Write-Host "No running Ollama processes found."
}

# --- 2. Set server environment variables (this process and its children only) ---
$env:OLLAMA_NUM_PARALLEL      = "$NumParallel"
$env:OLLAMA_MAX_LOADED_MODELS = "$MaxLoadedModels"
$env:OLLAMA_KEEP_ALIVE        = $KeepAlive

Write-Host "Ollama settings:"
Write-Host "  OLLAMA_NUM_PARALLEL      = $env:OLLAMA_NUM_PARALLEL"
Write-Host "  OLLAMA_MAX_LOADED_MODELS = $env:OLLAMA_MAX_LOADED_MODELS"
Write-Host "  OLLAMA_KEEP_ALIVE        = $env:OLLAMA_KEEP_ALIVE"

# --- 3. Start ollama serve in the background -------------------------------------
$logDir = Join-Path $PSScriptRoot "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$outLog = Join-Path $logDir "ollama-serve.log"
$errLog = Join-Path $logDir "ollama-serve.err.log"   # Ollama writes most of its logging here

Write-Host "Starting 'ollama serve' (logs in $logDir)..."
Start-Process -FilePath "ollama" -ArgumentList "serve" -NoNewWindow `
    -RedirectStandardOutput $outLog -RedirectStandardError $errLog | Out-Null

# --- 4. Wait until the API is answering ------------------------------------------
$deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $v = Invoke-RestMethod -Uri "$OllamaUrl/api/version" -TimeoutSec 2
        Write-Host "Ollama is up (version $($v.version))." -ForegroundColor Green
        $ready = $true
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}
if (-not $ready) {
    Write-Error "Ollama did not respond at $OllamaUrl within $StartupTimeoutSeconds seconds. Check $errLog."
}

# --- 5. Hand over to the normal launcher -----------------------------------------
$runScript = Join-Path $PSScriptRoot "run.ps1"
if (-not (Test-Path $runScript)) {
    Write-Error "Could not find $runScript."
}
& $runScript -local:$local
