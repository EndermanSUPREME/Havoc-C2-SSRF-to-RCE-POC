# Havoc-C2-SSRF-to-RCE-POC

This SSRF-RCE Chain was inspired by [chebuya's CVE-2024-41570 POC]([https://github.com/chebuya](https://github.com/chebuya/Havoc-C2-SSRF-poc)) and [IncludeSecurity's Havoc Auth RCE](https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc_auth_rce) both exploits are amazing and well crafted, please do give these creators appriciation for their hardwork!

- [chebuya](https://github.com/chebuya)
- [hyperreality](https://github.com/hyperreality)

The SSRF vulnerability works by spoofing a demon agent registration and checkins to open a TCP socket on the teamserver and read/write data from it.
The RCE vulnerability works by exploiting a flaw in Havoc's Payload creation by injecting code within the Service-Name allowing a Authenticated user to run commands on the teamserver.

With a teamserver's websocket port being inaccessible to the public, we can create functions that create WebSocket frames that we can push to the Closed/Filtered Teamserver port via the SSRF.

<i>Hackers (1995) - <b>Hack The Planet!</b></i>
