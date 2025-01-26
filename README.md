# Havoc-C2-SSRF-to-RCE-POC (Authenticated)

This SSRF-RCE Chain was inspired by [chebuya's CVE-2024-41570 SSRF POC](https://github.com/chebuya/Havoc-C2-SSRF-poc) and [IncludeSecurity's Havoc Auth RCE](https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc_auth_rce) both exploits are amazing and well crafted, please do give these creators appriciation for their hardwork!

- [chebuya](https://github.com/chebuya)
- [hyperreality](https://github.com/hyperreality)

### How does it Work?
The SSRF vulnerability works by spoofing a demon agent registration and checkins to open a TCP socket on the teamserver and read/write data from it.
The RCE vulnerability works by exploiting a flaw in Havoc's Payload creation by injecting code within the Service-Name, unfiltered string, allowing a Authenticated User to run System Commands on the teamserver.

With a teamserver's websocket port being inaccessible to the public, we can create functions that create WebSocket frames that we can push to the Closed/Filtered Teamserver port via the SSRF.

<details>
<summary><b>Consider the Following. . .</b></summary>
  <ul>
    <li>
      If the Teamserver port is <b>Closed/Filtered</b>, the Teamserver needs to be hosted on a non-secure web-socket server <i>(ws://)</i> for this POC to work.
      I'm not a networking or TLS protocol expert, but if there is potential to sent data successfully to a secure web-socket server <i>wss://</i> via the SSRF, this exploit could potentially have a wide impact.
    </li>
    <li>
      If the Teamserver port is <b>Open</b> and can be reached publically, you do not need to use the SSRF, if you have working credentials use the <i><a href="https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc_auth_rce">Auth-RCE</a></i> portion of the exploit.
    </li>
  </ul>
</details>

<i>Hackers (1995) - <b>Hack The Planet!</b></i>
