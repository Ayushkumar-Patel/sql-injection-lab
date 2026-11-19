# SQL Injection Lab — Web Application Security Assessment (DVWA + SQLmap)

A hands-on web application penetration test carried out in an isolated two-VM lab. The assessment identifies and exploits a SQL injection vulnerability in [DVWA](https://github.com/digininja/DVWA), extracts and cracks stored credentials with [SQLmap](https://sqlmap.org), documents the findings, and defines the remediation and detection logic to close the gap.

**Scope & ethics:** All testing was performed against a deliberately vulnerable application I own, on an isolated host-only network. SQL injection testing against systems without explicit authorization is illegal.

---

## Lab architecture

Two virtual machines on a private VMware **host-only** network — no exposure to the internet or the physical LAN.

```
          Host (Windows) — VMware Workstation Pro
 ┌───────────────────────────┐        ┌───────────────────────────┐
 │  Kali Linux  (attacker)   │        │  Ubuntu Server  (target)  │
 │  192.168.152.133          │        │  192.168.152.131          │
 │  - SQLmap 1.10.10         │ HTTP   │  - Docker                 │
 │  - Firefox                │ ─────▶ │  - DVWA (Apache+PHP)       │
 │  - Burp Suite (optional)  │        │  - MariaDB 10.1.26        │
 └───────────────────────────┘        └───────────────────────────┘
          └──────── Host-only network (192.168.152.0/24) ────────┘
```

| Component | Role | Details |
| --- | --- | --- |
| Kali Linux | Attacker | SQLmap, Firefox |
| Ubuntu Server | Target host | Docker running the DVWA container |
| DVWA | Vulnerable app | Apache + PHP, MariaDB backend |
| Network | Isolation | VMware host-only, no internet/LAN access |

---

## Methodology

| Step | Action |
| --- | --- |
| 1 | Built the two VMs and the isolated host-only network |
| 2 | Deployed DVWA on Ubuntu via Docker (`vulnerables/web-dvwa`) |
| 3 | Configured DVWA at **Low** security, located the `id` injection point |
| 4 | Confirmed the injection manually (error-based, boolean, `UNION`) |
| 5 | Automated detection, enumeration, extraction and hash cracking with SQLmap |
| 6 | Documented the finding (this repo) |
| 7 | Remediated with parameterized queries (DVWA **Impossible**) |
| 8 | Retested to confirm the injection was closed |

---

## Key finding

| Field | Value |
| --- | --- |
| Finding | SQL injection in the DVWA User ID parameter |
| Severity | **Critical** |
| CVSS 3.1 | 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (lab context) |
| Affected | `GET /vulnerabilities/sqli/`, parameter `id` |
| Weakness | CWE-89: Improper Neutralization of Special Elements in an SQL Command |

The `id` parameter is concatenated directly into a SQL query with no parameterization. An attacker can read arbitrary data from the database, including all stored credentials.

### Manual confirmation (Step 4)

| Input | Result |
| --- | --- |
| `'` | SQL syntax error — injection confirmed |
| `1' OR '1'='1` | Returned all users |
| `1' ORDER BY 2 / 3-- -` | Query has 2 columns |
| `1' UNION SELECT user, password FROM users-- -` | Dumped usernames + password hashes |
| `1' UNION SELECT @@version, database()-- -` | MariaDB 10.1.26, database `dvwa` |

### Automated extraction (Step 5)

SQLmap confirmed four injection techniques (boolean, error-based, time-based, UNION), enumerated the database, dumped the `users` table, and cracked every MD5 hash against its wordlist:

| User | Hash (MD5) | Cracked password |
| --- | --- | --- |
| admin | `5f4dcc3b5aa765d61d8327deb882cf99` | password |
| gordonb | `e99a18c428cb38d5f260853678922e03` | abc123 |
| 1337 | `8d3533d75ae2c3966d7e0d4fcc69216b` | charley |
| pablo | `0d107d09f5bbe40cade3de5c71e9e9b7` | letmein |
| smithy | `5f4dcc3b5aa765d61d8327deb882cf99` | password |

**Impact:** full read access to the application database and complete compromise of all user credentials.

---

## Remediation

The root cause is string concatenation of user input into SQL. The fix is **parameterized queries (prepared statements)**, which separate code from data:

```php
$stmt = $conn->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
```

Defense in depth:
- Input validation (cast `id` to integer, reject non-numeric)
- Least-privilege database account (`SELECT` only)
- Suppress raw SQL errors in responses
- Web application firewall (ModSecurity + OWASP CRS)

Verified by raising DVWA to **Impossible** and re-running SQLmap with `--level=5 --risk=3` — the parameter was reported as not injectable.

---

## Detection (blue team)

The attack is clearly visible in the target's Apache access log (`evidence/12-dvwa-apache-sqli-attack.log`). Detection signals:

- **SQLmap user-agent** — `sqlmap/1.10.10#stable` on every automated request
- **Request volume/rate** — ~180 requests in ~2 seconds (no human pattern)
- **SQL keywords in query strings** — `UNION ALL SELECT`, `information_schema`, `ORDER BY`, `SLEEP(5)`, `BENCHMARK`
- **URL-encoded injection characters** — `%27` (`'`), hex-encoded strings

These map directly to SIEM detection rules for SQL injection and automated scanning.

---

## Repository structure

```
sql-injection-lab/
├── README.md              # this file
├── docs/
│   └── report.md          # full assessment write-up
├── screenshots/           # 01–11, manual testing + SQLmap evidence
└── evidence/
    ├── users-dump.csv             # cracked users table
    └── 12-dvwa-apache-sqli-attack.log   # target-side attack log
```

---

## Tools

VMware Workstation Pro · Kali Linux · Ubuntu Server · Docker · DVWA · SQLmap · Firefox

## Author

**Ayushkumar Patel** — CompTIA Security+
[GitHub](https://github.com/Ayushkumar-Patel) · [LinkedIn](https://www.linkedin.com/in/ayushh-patell/)
