#!/bin/bash
# yaklite menu bar shield for SwiftBar (https://swiftbar.app) or xbar.
# Install: copy this file into your SwiftBar plugins folder and make it
# executable. It reads the local dashboard every minute; nothing leaves the Mac.
#
# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>
# <swiftbar.hideLastUpdated>false</swiftbar.hideLastUpdated>

BIN="$HOME/Library/Application Support/yaklite/yaklite"
JSON=$(curl -fsS --max-time 3 http://127.0.0.1:9842/api/summary 2>/dev/null)
if [ -z "$JSON" ]; then
  echo "🛡 ?"
  echo "---"
  echo "yaklite dashboard is not running | color=gray"
  echo "Start it: yaklite install | bash='$BIN' param1=install terminal=true"
  exit 0
fi
field() { /usr/bin/python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('$1'); print(v if not isinstance(v,list) else '\n'.join(v))" <<<"$JSON"; }
STATUS=$(field status)
case "$STATUS" in
  alert) echo "🛡❗ | color=red" ;;
  warn)  echo "🛡⚠︎ | color=orange" ;;
  *)     echo "🛡✓" ;;
esac
echo "---"
echo "Serious problems: $(field open_high)"
echo "Worth a look: $(field open_medium)"
echo "Alerts in the last 24h: $(field alerts_24h)"
echo "Last check: $(field last_check)"
TOP=$(field top_problems)
if [ -n "$TOP" ]; then
  echo "---"
  while IFS= read -r line; do echo "${line:0:90} | size=12"; done <<<"$TOP"
fi
echo "---"
echo "Open dashboard | href=http://127.0.0.1:9842/"
echo "Check now | bash='$BIN' param1=auto param2=--min-interval param3=0 terminal=false refresh=true"
echo "Network status | bash='$BIN' param1=status terminal=true"
