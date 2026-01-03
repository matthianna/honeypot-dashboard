# Honeypot Attack Report
**Period:** Last 30 Days  
**Report Date:** December 31, 2025

---

## Executive Summary

Our honeypot infrastructure recorded **over 4.2 million events** from **36,052 unique attackers** across 6 different honeypots and a firewall monitoring system.

| Component | Total Events | Unique Attackers |
|-----------|-------------|------------------|
| **Firewall** | 2,865,137 | 27,725 |
| **Cowrie (SSH)** | 836,271 | 2,968 |
| **Dionaea (Malware)** | 264,256 | 1,761 |
| **RDPY (RDP)** | 216,871 | 820 |
| **Heralding (Multi-Protocol)** | 40,286 | 2,398 |
| **Galah (Web/LLM)** | 1,712 | 380 |
| **Total** | **4,224,533** | **36,052** |

---

## 1. Cowrie SSH Honeypot

Cowrie is our SSH honeypot that captures login attempts and commands. We deployed **3 variants** to compare attacker behavior:

### Variant Comparison

| Variant | Events | Unique IPs | Sessions | Commands |
|---------|--------|------------|----------|----------|
| **Plain** (Standard) | 342,025 | 1,999 | 27,076 | 13,999 |
| **OpenAI** (GPT-powered) | 274,783 | 359 | 16,952 | 36 |
| **Ollama** (Local LLM) | 219,493 | 1,071 | 38,282 | 10 |

**Key Finding:** The Plain variant received the most commands (13,999), while LLM variants received very few commands. This suggests attackers may detect unusual behavior from LLM responses and abort their attacks.

### Top Credentials Attempted

| Username | Password |
|----------|----------|
| root | 1q2w3e4r |
| root | password123 |
| root | 123321 |
| root | 123123 |
| test | test123 |
| test | 123456 |
| test | password |

---

## 2. Dionaea Malware Honeypot

Dionaea captures malware and exploits targeting network services.

- **Total Events:** 264,256
- **Unique Attackers:** 1,761

### Top Attacking Countries

| Country | Events | % of Total |
|---------|--------|------------|
| 🇸🇨 Seychelles | 125,657 | 47.5% |
| 🇭🇰 Hong Kong | 47,443 | 18.0% |
| 🇦🇺 Australia | 27,336 | 10.3% |
| 🇩🇪 Germany | 17,738 | 6.7% |
| 🇺🇸 United States | 12,777 | 4.8% |
| 🇻🇳 Vietnam | 6,911 | 2.6% |
| 🇷🇺 Russia | 5,770 | 2.2% |
| 🇫🇷 France | 4,927 | 1.9% |
| 🇨🇳 China | 3,060 | 1.2% |

**Note:** Seychelles accounts for nearly half of all Dionaea attacks. This is likely due to VPN services, proxy servers, or bulletproof hosting providers operating from that region.

---

## 3. RDPY (RDP) Honeypot

RDPY simulates a Windows Remote Desktop server to capture RDP attacks.

- **Total Events:** 216,871
- **Unique Attackers:** 820

### Top Attacking Countries

| Country | Events | % of Total |
|---------|--------|------------|
| 🇧🇬 Bulgaria | 74,844 | 34.5% |
| 🇨🇳 China | 8,827 | 4.1% |
| 🇺🇸 United States | 5,031 | 2.3% |
| 🇲🇾 Malaysia | 3,135 | 1.4% |
| 🇩🇪 Germany | 3,092 | 1.4% |
| 🇵🇰 Pakistan | 1,964 | 0.9% |
| 🇻🇳 Vietnam | 1,854 | 0.9% |
| 🇮🇳 India | 1,683 | 0.8% |

**Note:** Bulgaria dominates RDP attacks (34.5%), which is unusual. This suggests coordinated attacks from specific infrastructure in that region.

---

## 4. Heralding Multi-Protocol Honeypot

Heralding captures credential attacks across multiple protocols.

- **Total Events:** 40,286
- **Unique Attackers:** 2,398

### Protocol Distribution

| Protocol | Sessions | Unique IPs |
|----------|----------|------------|
| **VNC** | 19,348 | 191 |
| **Telnet** | 12,360 | 896 |
| **HTTP** | 2,164 | 381 |
| **MySQL** | 1,522 | 198 |
| **SMTP** | 1,293 | 89 |
| **HTTPS** | 1,193 | 336 |
| **SOCKS5** | 619 | 111 |
| **PostgreSQL** | 575 | 142 |

### Top Attacking Countries

| Country | Events | % of Total |
|---------|--------|------------|
| 🇩🇪 Germany | 18,677 | 46.4% |
| 🇺🇸 United States | 5,472 | 13.6% |
| 🇺🇦 Ukraine | 2,447 | 6.1% |
| 🇸🇪 Sweden | 2,227 | 5.5% |
| 🇸🇬 Singapore | 1,624 | 4.0% |
| 🇳🇱 Netherlands | 1,420 | 3.5% |
| 🇨🇳 China | 1,350 | 3.4% |

**Key Finding:** VNC and Telnet are the most attacked protocols, followed by database services (MySQL, PostgreSQL). Germany is the top source, likely due to hosting providers.

---

## 5. Galah Web Honeypot (LLM-Powered)

Galah is an innovative web honeypot that uses AI (LLM) to generate dynamic responses to attackers.

- **Total Events:** 1,712
- **Unique Attackers:** 380

### Top Attacking Countries

| Country | Events | % of Total |
|---------|--------|------------|
| 🇺🇸 United States | 417 | 24.4% |
| 🇳🇱 Netherlands | 228 | 13.3% |
| 🇬🇧 United Kingdom | 183 | 10.7% |
| 🇩🇪 Germany | 171 | 10.0% |
| 🇸🇬 Singapore | 75 | 4.4% |
| 🇫🇷 France | 73 | 4.3% |
| 🇵🇱 Poland | 72 | 4.2% |
| 🇨🇳 China | 61 | 3.6% |

---

## 6. Firewall Analysis

Our firewall monitors all incoming traffic to the honeypot infrastructure.

### Traffic Statistics
- **Total Events:** 2,865,137
- **Unique Source IPs:** 27,725

### Top Attacking Countries

| Country | Events | % of Total |
|---------|--------|------------|
| 🇨🇭 Switzerland | 525,961 | 18.4% |
| 🇧🇷 Brazil | 519,180 | 18.1% |
| 🇧🇬 Bulgaria | 270,286 | 9.4% |
| 🇺🇸 United States | 250,894 | 8.8% |
| 🇳🇱 Netherlands | 97,164 | 3.4% |
| 🇸🇨 Seychelles | 64,215 | 2.2% |
| 🇷🇴 Romania | 62,402 | 2.2% |
| 🇩🇪 Germany | 41,572 | 1.5% |
| 🇨🇳 China | 29,564 | 1.0% |
| 🇭🇰 Hong Kong | 24,722 | 0.9% |

---

## 7. Geographic Analysis Summary

Each honeypot shows different geographic patterns, suggesting different attack campaigns target different services:

| Honeypot | #1 Country | % | Likely Reason |
|----------|-----------|---|---------------|
| **Firewall** | Switzerland | 18.4% | VPN/Proxy services |
| **Dionaea** | Seychelles | 47.5% | Bulletproof hosting |
| **RDPY** | Bulgaria | 34.5% | Coordinated RDP attacks |
| **Heralding** | Germany | 46.4% | Hosting providers |
| **Galah** | USA | 24.4% | Web scanners |

**Interpretation:** The geographic distribution does not represent actual attacker locations but rather the location of:
- VPN and proxy services
- Bulletproof hosting providers
- Compromised servers used as attack infrastructure
- Cloud service providers

---

## 8. Key Findings

1. **High Volume of Attacks:** Over 4.2 million events in 30 days shows constant automated scanning and attacks.

2. **SSH is Most Targeted:** Cowrie (SSH) received the highest honeypot-specific traffic with 836,271 events.

3. **LLM Honeypots Show Different Behavior:** LLM-powered variants received significantly fewer commands than the plain variant - attackers may detect unusual AI responses.

4. **Geographic Anomalies:** Small countries like Seychelles (47% of Dionaea) and Bulgaria (34% of RDPY) show unusually high attack volumes, indicating use of anonymizing infrastructure.

5. **Credential Attacks are Simple:** Most attempted passwords are very simple (123456, password, test), showing reliance on automated tools with common password lists.

6. **Protocol Diversity:** Attackers target many different services, with VNC and Telnet being popular targets alongside SSH and RDP.

---

## 9. Conclusion

The honeypot infrastructure successfully captured significant attack data over 30 days. Key takeaways:

- Automated attacks are constant and high-volume
- SSH remains the most targeted service
- LLM-powered honeypots show promise for future research
- Geographic data shows infrastructure locations, not real attacker locations
- Simple credentials are still commonly attempted

This data provides valuable insights for understanding attacker behavior and improving security measures.

---

*Report generated from honeypot data collected December 1-31, 2025.*
