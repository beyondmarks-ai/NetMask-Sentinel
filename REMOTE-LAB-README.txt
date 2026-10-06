NetMask Sentinel - Remote Authorized Lab Test
================================================

Purpose
-------
This package creates bounded TCP connections, pings, and ordinary HTTP requests
from a second computer so you can validate NetMask Sentinel on a private lab
network. It contains no exploits, credential attempts, or destructive payloads.

Requirements
------------
- Windows 10/11 on the second computer. Python is NOT required.
- Both computers connected to the same private network.
- Explicit authorization to test the target computer.

Steps
-----
1. On the NetMask computer, double-click "NetMask Sentinel.lnk".
2. Run ipconfig and note its private IPv4 address.
3. Copy and extract the complete ZIP on the second computer.
4. Double-click "Run Remote Lab Test.cmd".
5. Enter the private IP, choose a profile, and type AUTHORIZED.
6. Watch Captured Flow and Recent Incidents on the NetMask dashboard.

Profiles
--------
- baseline: low-rate normal validation.
- burst: bounded traffic spike.
- discovery: bounded connection-only private port pattern.
- alert: a token-protected, labelled dashboard alert that records the tester's
  source IP. It sends no attack payload. On the sensor computer, run
  `Show-LabAlertToken.ps1` and enter that token when prompted.

The NetMask-Lab-Test folder is self-contained and uses no Python installation. Keep the folder and its _internal subfolder together. The included Python
source is only a fallback and for transparency. The program refuses public IP
addresses. Detection is model-dependent, so a profile may be classified as
benign; it still validates packet capture and flow processing.
