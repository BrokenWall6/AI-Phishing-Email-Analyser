#!/usr/bin/env bash
# Start the Ollama server in CPU-only mode (Git Bash).
#
# Useful when the CUDA backend crashes on startup
# ("CUDA error: shared object initialization failed" / 0xc0000409) or the
# GPU runs out of memory. The variables only apply to a server started
# after they are set, so quit the Ollama tray app first.
#
# Usage:  bash scripts/start_ollama_cpu.sh
# Keep this window open. Test in a second window with:
#   ollama run qwen3:4b "Reply with only: OK"

if tasklist 2>/dev/null | grep -qi "ollama"; then
    echo "Ollama is already running."
    echo "Quit it first: system tray (^ arrow) -> right-click Ollama -> Quit, then run this again."
    exit 1
fi

echo "Starting Ollama in CPU-only mode on http://127.0.0.1:11434 ..."
CUDA_VISIBLE_DEVICES=-1 OLLAMA_VULKAN=0 OLLAMA_CONTEXT_LENGTH=2048 ollama serve
