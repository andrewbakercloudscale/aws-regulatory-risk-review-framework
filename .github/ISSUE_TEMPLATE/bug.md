---
name: Bug
about: Something failed or the report looks wrong
labels: bug
---

**What happened** (command or UI step, and the error):

**Expected:**

**Log lines** — `jq 'select(.run_id=="<scan id>")' ~/.exitrisk/logs/exitrisk.log` (remove sensitive account names):

**Versions** — `exitrisk --version`, catalog version (report footer), Python, OS:
