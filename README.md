# Threat Hunt: RDP Brute-Force Attack on Internet-Facing Windows Hosts

**Lab environment:** Microsoft Sentinel Training Lab dataset (`SecurityEvent`)
**SC-200 domain:** Perform threat hunting · Respond to security incidents
**Detection surface:** Microsoft Sentinel (Defender portal) · KQL

---

## Summary

Hunting Windows security events for signs of password-guessing activity, I identified a large-scale brute-force attack against two internet-facing hosts. The attacker generated over 10,000 failed logons against common and default account names — a classic dictionary spray. I then verified whether any attempt succeeded and confirmed the attack **failed**: no targeted account achieved a logon, and the only successful sign-ins on the affected hosts were the built-in `SYSTEM` account (normal OS activity, not an intrusion).

**Verdict:** True positive — a genuine brute-force attack occurred, but was **unsuccessful**. Severity: low/contained, with a hardening gap to remediate.

---

## Environment note

Performed in a lab tenant using Microsoft's Sentinel Training Lab dataset. The Windows telemetry lands in the standard `SecurityEvent` table, so the logic and Event IDs used here transfer directly to a production environment.

---

## Scenario & hypothesis

An attacker who does not already hold valid credentials will attempt to guess them — firing large volumes of password attempts against an account. This produces a distinctive fingerprint: a high count of **failed logons** against one or more accounts in a short period.

**Hypothesis:** Accounts with an abnormally high number of failed logons are candidates for an active brute-force attack.

**Key concept — Windows logon Event IDs:** unlike Okta's text-based result field, Windows encodes logon outcomes numerically:
- `4625` = failed logon
- `4624` = successful logon

---

## Hunt methodology

### Step 1 — Surface the failed-logon pile

Count failed logons per account to find who is being hammered.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogin = count() by Account
| order by FailedLogin desc
```

**Result (top rows):**

| Account | FailedLogin |
|---|---|
| \ADMINISTRATOR | 10,255 |
| \admin | 1,989 |
| \administrator | 1,864 |
| \ADMIN | 598 |
| \USER, \TEST, \SERVER … | hundreds each |
| \ADMINISTRADOR, \ADMINISTRATEUR | tens each |

The pattern itself is diagnostic. The list is dominated by **common default usernames** and **localised admin names** (`ADMINISTRADOR` – Spanish, `ADMINISTRATEUR` – French). A human would not guess these; an automated tool with a built-in wordlist would. This is a **dictionary spray** — the attacker is guessing both usernames *and* passwords, so most of these accounts likely do not even exist on the target. A failed logon is recorded regardless of whether the account exists.

### Step 2 — Add the target asset

Grouping by `Computer` reveals *what* is under attack.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogin = count() by Account, Computer
| order by FailedLogin desc
```

**Result:** failures cluster on two hosts:
- **`SOC-FW-RDP`** — `ADMINISTRATOR` alone hit 9,997 times, plus `ADMIN`, `USER`, `TEST`, `SERVER`, and foreign-language admin variants.
- **`SHIR-Hive`** — `admin` / `administrator` hammered ~2,000+ times each.

The host name `SOC-FW-RDP` is itself a signal: an internet-facing **RDP** (Remote Desktop Protocol) server. Internet-exposed RDP is one of the most heavily brute-forced services in existence — attackers continuously scan for and spray open RDP endpoints.

**Source limitation:** `IpAddress` was empty for the attack rows. On certain Windows `4625` logon types the source IP is not populated in `IpAddress`, and may appear in alternate fields (`WorkstationName`, `ClientAddress`). This left the attacker's source unidentified — an important gap for response, and a logging improvement to flag.

### Step 3 — The severity-defining question: did it succeed?

Failures alone mean the attacker knocked but may not have entered. I pivoted to successful logons (`4624`) on the affected hosts.

```kql
SecurityEvent
| where EventID == 4624
| summarize SuccessfulLogin = count() by Account, Computer
| order by SuccessfulLogin desc
```

**Result on the attacked hosts:**
- `SOC-FW-RDP` → only `NT AUTHORITY\SYSTEM` (10)
- `SHIR-Hive` → only `NT AUTHORITY\SYSTEM` (4)

**No `administrator`, no `admin`, no attacker-guessed account succeeded.**

---

## Findings & analysis

**The brute force failed.** No targeted account achieved a successful logon on either host.

**Critical read — filtering out built-in accounts:** the only "successes" on the attacked hosts were `NT AUTHORITY\SYSTEM`. This is **not a user or an attacker** — it is the local machine/OS account, which logs on continuously as part of normal Windows operation. Treating a `SYSTEM` logon as an intrusion is a common false-alarm; recognising built-in and service accounts (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, and machine accounts ending in `$` such as `ADMINPC2$`) as benign is essential to avoid crying wolf.

The remaining successful logons elsewhere (`CONTOSO\SamiraA`, `CONTOSO\RonHD`, `AATPService`) are legitimate domain activity on other machines, unrelated to the attack.

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1110.001 – Brute Force: Password Guessing | 10,000+ failed logons against default account names |
| Credential Access | T1110.003 – Brute Force: Password Spraying | Wide spread of guessed usernames across hosts |
| Initial Access | T1133 – External Remote Services | Internet-facing RDP host (`SOC-FW-RDP`) as the entry point targeted |

---

## Verdict & response

**Verdict:** True positive, **unsuccessful** brute-force attack against `SOC-FW-RDP` and `SHIR-Hive`. No compromise occurred, but the hosts are exposed and under continuous attack.

**Recommended hardening (root-cause focused, since the attacker's source could not be blocked):**

1. **Remove RDP from direct internet exposure** — the root fix. Place RDP behind a VPN or bastion/jump host, or restrict it to known admin source IPs. If the service is unreachable from the open internet, the attack never begins.
2. **Enforce an account lockout policy** — lock accounts after a small number of failed attempts (e.g. 5) for a set duration. This makes high-volume guessing mechanically impossible without needing to identify the attacker. *Caveat:* lockout can be abused for denial-of-service (deliberately locking legitimate users), so pair it with monitoring rather than treating it as a complete solution.
3. **Enforce MFA** on remote-access accounts so a correct password guess alone is insufficient to authenticate.
4. **Improve logging** to reliably capture the source of `4625` events (workstation/IP), removing the blind spot that prevented source attribution in this investigation.

---

## Lessons learned

- **A failed attack is still a true positive.** "True positive, unsuccessful" ≠ "false positive." The detection was correct; the attack simply did not work.
- **The shape of the data reveals the tooling.** Foreign-language admin names and default usernames are the fingerprint of an automated dictionary spray, not human activity.
- **Read the asset name.** `SOC-FW-RDP` telegraphs an internet-facing RDP box — high-value context before any query runs.
- **Know your built-in accounts.** `SYSTEM` and machine (`$`) accounts logging on successfully is normal; mistaking them for intrusions produces false escalations.
- **"Field is empty" ≠ "data doesn't exist."** Source detail may live in an alternate column; a blank field is a prompt to look elsewhere, not a dead end.
- **When you can't fix the attacker, harden the victim.** No source IP to block → pivot to root-cause hardening of the exposed asset.

---

## Skills demonstrated

Threat hunting with KQL · Windows Event ID analysis (4624/4625) · Attack-pattern recognition · Success/failure verification · Built-in vs. malicious account triage · Root-cause hardening recommendations · MITRE ATT&CK mapping
