#!/bin/bash

# Ranges of parameters to test
DELAYS=(0.01 0.05 0.1 0.2 0.4 0.8)
REPEATS=(1)

TEXT_FILE="covert_text.txt"

# Check if file exists
if [ ! -f "$TEXT_FILE" ]; then
  echo "[!] File '$TEXT_FILE' not found!"
  exit 1
fi

# Create a results directory if not exists
mkdir -p sender_results

# Main experiment loop
for delay in "${DELAYS[@]}"; do
  for repeat in "${REPEATS[@]}"; do
    LOGFILE="sender_results/log_delay${delay}_rep${repeat}.csv"
    
    echo "[*] Running: delay=$delay, repeat=$repeat"
    ./sender "$TEXT_FILE" --delay="$delay" --repeat="$repeat" --logfile="$LOGFILE"
    
    echo "[✔] Done: $LOGFILE"
    echo ""
  done
done

echo "[✓] All sender experiments complete."
