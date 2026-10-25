# Start the Ollama server in CPU-only mode (PowerShell).
#
# Useful when the CUDA backend crashes on startup
# ("CUDA error: shared object initialization failed" / 0xc0000409) or the
# GPU runs out of memory. The variables only apply to a server started
# after they are set, so quit the Ollama tray app first.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\start_ollama_cpu.ps1
# Keep this window open while you use the app. Test in a second window with:
#   ollama run qwen3:4b "Reply with only: OK"

$running = Get-Process -Name "ollama*" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "Ollama is already running (PID: $($running.Id -join ', '))." -ForegroundColor Yellow
    Write-Host "Quit it first: system tray (^ arrow) -> right-click Ollama -> Quit, then run this script again."
    exit 1
}

$env:CUDA_VISIBLE_DEVICES = "-1"      # hide the NVIDIA GPU from the CUDA backend
$env:OLLAMA_VULKAN = "0"              # do not fall back to the Vulkan GPU backend
$env:OLLAMA_CONTEXT_LENGTH = "2048"   # smaller context = less RAM

Write-Host "Starting Ollama in CPU-only mode on http://127.0.0.1:11434 ..." -ForegroundColor Green
ollama serve
