# APT28 Detection Lab

This project is based on the TryHackMe Eviction room, where the APT28
group (also known as Fancy Bear) is simulated attacking a company called
E-Corp. The goal was to practise detection engineering by mapping the
attacker's behaviours to MITRE ATT&CK and writing Sigma rules for them.

I covered 12 techniques across the attack lifecycle, but I only wrote
full Sigma rules for 3 of them — Registry Run Keys persistence, Rundll32
proxy execution, and tcpdump network sniffing. I chose those three
because they were the ones I felt most confident explaining. The other 9
are listed below as next steps.

## Techniques mapped

- Resource Development: Compromise Email Accounts (T1586.002)
- Execution: Malicious File (T1204.001), Malicious Link (T1204.002), PowerShell (T1059.001), Windows Command Shell (T1059.003)
- Persistence: Registry Run Keys (T1547.001)
- Defense Evasion: Rundll32 (T1218.011)
- Discovery: Network Sniffing (T1040)
- Lateral Movement: SMB/Admin Shares (T1021.002)
- Collection: SharePoint (T1213.002)
- Command and Control: External Proxy (T1090.002), Multi-hop Proxy (T1090.003)

## Sigma rules I wrote

**Registry Run Keys (T1547.001)** — detects modification of the
`CurrentVersion\Run` and `RunOnce` registry keys, with a filter for
known legitimate installers like OneDrive and Teams.

**Rundll32 (T1218.011)** — detects `rundll32.exe` loading DLLs from
user-writable paths like `AppData`, `Temp`, and `Users\Public`.

**Network Sniffing (T1040)** — detects packet capture tools like
`tcpdump`, `windump`, `tshark`, and `dumpcap` running on Windows hosts.

The rules are simple and I wrote them while learning Sigma syntax, so
they would need tuning before real use.

## What I struggled with

The `condition` logic in Sigma took me a while to understand, especially
the difference between `selection` and `filter`. I also found it hard to
write realistic false positive notes because I have not seen these
behaviours in a real environment yet.

## What I would do next

- Write rules for the remaining 9 techniques
- Test these rules against real Sysmon logs in a lab
- Learn how to convert Sigma rules to Splunk format
- Read how other analysts tune rules for production

## Reference

- TryHackMe Eviction room
- MITRE ATT&CK page for APT28 (G0007)
