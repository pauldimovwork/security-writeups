# Detecting a DNS Tunneling C2 Channel with Wireshark

**Network traffic analysis · October 2026**

> Analysis of a one-hour packet capture from a compromised lab host. I identified
> a DNS tunneling command-and-control (C2) channel built with **dnscat2**
> (MITRE ATT&CK [T1071.004](https://attack.mitre.org/techniques/T1071/004/)),
> decoded how it worked, and documented it as an incident report.

**Result:** 93.1% of the capture (13,783 of 14,806 packets) was C2 traffic between
host `10.20.57.3` and the attacker domain `cisco-update.com`, carried over two
concurrent dnscat2 sessions.

> **Lab environment.** This analysis was performed on a provided training packet
> capture in an isolated lab. No production systems were involved, and no traffic
> was generated against any system I was not authorized to test.

---

## Contents

- [Background](#background)
- [Tools & skills](#tools--skills)
- [Approach](#approach)
- [Key findings](#key-findings)
- [Detection ideas for a SOC](#detection-ideas-for-a-soc)
- [Recommended response](#recommended-response)
- [What I learned](#what-i-learned)
- [References](#references)

---

## Background

DNS tunneling hides attacker traffic inside ordinary domain lookups, which most
networks allow through the firewall and rarely inspect.

The malware on the infected host never contacts the attacker directly. It looks up
made-up subdomains of `cisco-update.com`, and the internal DNS resolvers
(`10.10.2.22` and `10.10.2.21`) forward each lookup to the domain's authoritative
name server, which the attacker controls. Outbound data is hidden in the hex
subdomain of each query; commands come back inside TXT, CNAME, and MX answers.

The goal was to find the channel using only Wireshark, explain how it works, and
write it up as an incident report.

---

## Tools & skills

| Area | Used in this project |
|---|---|
| **Tools** | Wireshark (display filters, packet details, hex view, Follow UDP Stream, I/O Graphs), tshark, CyberChef |
| **Protocols** | DNS (record types, resolvers, authoritative name servers, caching), UDP, Ethernet/IPv4 headers |
| **Techniques** | Traffic baselining, beacon detection, protocol decoding, IOC extraction, incident reporting |
| **Frameworks** | MITRE ATT&CK T1071.004 (Application Layer Protocol: DNS) |

---

## Approach

1. **Verified evidence integrity.** Checked the PCAP's SHA-256 hash against the
   published value before analysis.
2. **Baselined the traffic.** Used Protocol Hierarchy and Conversations to see that
   DNS dominated the capture — abnormal for a workstation.
3. **Isolated the suspect domain.** Added the query name as a column and filtered
   with `dns.qry.name contains "cisco-update"`, which matched 13,783 packets.
4. **Inspected individual packets.** Examined record types, name lengths, and the
   encoded subdomain in the packet details and hex view.
5. **Decoded the protocol.** Mapped the hex prefix to the dnscat2 packet header
   (packet ID, message type, session ID) and found two session IDs, `0x8ea0` and
   `0x6cb1`.
6. **Measured timing.** Built an I/O graph at 2-second intervals to show the steady
   polling beacon and bursts of real data transfer.
7. **Ruled out legitimate use.** Confirmed there was no HTTP or TLS connection to the
   domain after any lookup.
8. **Reported.** Documented IOCs, findings, limitations, and containment steps.

<!-- Add your screenshots to an images/ folder and uncomment:
![Wireshark packet list](images/packet-list.jpg)
*Figure 1. Queries from 10.20.57.3 rotate MX, CNAME and TXT, each with a unique hex-encoded subdomain of cisco-update.com.*

![I/O graph](images/io-graph.jpg)
*Figure 2. I/O graph at 2-second intervals: a steady polling baseline for the full hour, with spikes where data was transferred.*
-->

---

## Key findings

- **Volume:** 93.1% of all packets were lookups and answers for one domain — about
  one query per second for the full hour.
- **Encoded data:** every query used a unique hex subdomain (for example
  `e7f1018ea0310f25bba0610936fd1cc2af.cisco-update.com`), which defeats DNS caching
  and forces each lookup to reach the attacker.
- **Two-way channel:** queries rotated MX, CNAME, and TXT types; responses
  (169–217 bytes) carried hex data back from the C2 server.
- **Encrypted payload:** decoded data past the dnscat2 header was high-entropy,
  consistent with dnscat2's default encryption — detection relied on behavior
  rather than content.
- **No legitimate use:** no web or TLS connection ever followed the lookups.

### Indicators of compromise (IOCs)

| Type | Value |
|---|---|
| Domain | `cisco-update.com` |
| Infected host | `10.20.57.3` |
| dnscat2 session IDs | `0x8ea0`, `0x6cb1` |
| Behavior | High-volume unique-subdomain lookups to a single root domain; rotating MX/CNAME/TXT; no follow-on HTTP/TLS |

---

## Detection ideas for a SOC

- Alert on high counts of **unique subdomains per root domain** from a single host.
- Flag **unusually long query names** and high-entropy labels.
- Watch for **high TXT / MX / CNAME volumes** originating from workstations.
- Correlate DNS lookups with the **absence of a follow-on connection** to the same
  domain.

---

## Recommended response

- Isolate `10.20.57.3` and preserve disk and memory images.
- Block or sinkhole `cisco-update.com` on internal resolvers; check logs for other
  hosts querying it.
- Force endpoints to use internal resolvers and block outbound DNS elsewhere.

---

## What I learned

- **Resolvers are relays, not targets.** The attacker never compromises DNS
  infrastructure; they own an authoritative domain and let normal recursion deliver
  the traffic.
- **Behavior beats content.** When the payload is encrypted, volume, uniqueness,
  record-type mix, timing, and the missing follow-up connection still expose the
  channel.
- **Protocol knowledge pays off.** Recognizing the dnscat2 header turned
  random-looking hex into session IDs and message types, revealing two concurrent
  sessions.

---

## References

- [MITRE ATT&CK T1071.004: Application Layer Protocol — DNS](https://attack.mitre.org/techniques/T1071/004/)
- [dnscat2 project](https://github.com/iagox86/dnscat2)
