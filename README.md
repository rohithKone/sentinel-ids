# Sentinel IDS

A small, passive network intrusion detection starter with an optional local web dashboard. It watches IPv4 TCP traffic for possible port scans, SYN bursts, and connections to watched ports (21, 23, 445, 3389, 4444).

## Install

Python 3.10+ is recommended. Install Scapy:

```powershell
python -m pip install -r requirements.txt
```

On Windows, packet capture usually requires Administrator privileges and Npcap. Monitor only networks you are authorized to observe.

## Start the IDS and dashboard

```powershell
python -m src.ids --interface "Ethernet" --dashboard
```

Open **http://127.0.0.1:8765** in your browser. The dashboard is served locally and shows live packet counts and detections. Alerts are also printed in the terminal and appended to `alerts.jsonl`.

Choose another dashboard port with `--dashboard-port 9000`. To print alerts without writing a file, add `--no-file`.

Without the dashboard, run the command as before:

```powershell
python -m src.ids --interface "Ethernet" --output alerts.jsonl
```

For a narrower capture:

```powershell
python -m src.ids --interface "Ethernet" --filter "tcp" --dashboard
```

Stop capture with Ctrl+C.

## Tune

Defaults are a 10-second window, 12 unique ports for scan alerting, and 40 SYN packets for burst alerting. Adjust with `--window`, `--port-scan-threshold`, and `--syn-threshold`. Detection is heuristic and can produce false positives; tune against traffic you understand before relying on it.

## Scope

This is an educational starter, not a production security monitor. It currently inspects IPv4 TCP headers only, keeps recent dashboard events in memory, and does not validate TCP connection outcomes or correlate hosts. Packet capture requires Scapy, Npcap on Windows, and appropriate privileges. The dashboard binds to localhost only.

