import type { Severity } from "@/lib/types"

interface ClassificationResult {
  title: string
  description: string
  severity: Severity
  mitreTactic: string
  mitreTechnique: string
}

interface DetectionRule {
  pattern: RegExp
  title: string
  description: string
  severity: Severity
  mitreTactic: string
  mitreTechnique: string
}

const detectionRules: DetectionRule[] = [
  {
    pattern: /beacon|c2|command.?and.?control|callback.*interval|sleep.*jitter/i,
    title: "C2 Beacon Activity Detected",
    description: "Network traffic patterns consistent with command-and-control beacon communication.",
    severity: "critical",
    mitreTactic: "Command and Control",
    mitreTechnique: "T1071 - Application Layer Protocol",
  },
  {
    pattern: /mimikatz|lsass.*dump|credential.*dump|sekurlsa|wdigest|kerberos.*ticket.*export/i,
    title: "Credential Dumping Attempt",
    description: "Activity consistent with credential harvesting from memory or credential stores.",
    severity: "critical",
    mitreTactic: "Credential Access",
    mitreTechnique: "T1003 - OS Credential Dumping",
  },
  {
    pattern: /sql.*injection|union\s+select|or\s+1\s*=\s*1|;\s*drop\s+table|xp_cmdshell|waitfor\s+delay/i,
    title: "SQL Injection Attempt",
    description: "Potential SQL injection attack detected in request parameters.",
    severity: "high",
    mitreTactic: "Initial Access",
    mitreTechnique: "T1190 - Exploit Public-Facing Application",
  },
  {
    pattern: /brute.?force|failed.*login.*(?:attempts?|count).*(?:\d{2,})|authentication.*fail.*repeated|lockout/i,
    title: "Brute Force Authentication Attack",
    description: "Multiple failed authentication attempts indicating brute force attack.",
    severity: "high",
    mitreTactic: "Credential Access",
    mitreTechnique: "T1110 - Brute Force",
  },
  {
    pattern: /tor\s+exit|\.onion|tor.*network|anonymiz|i2p.*tunnel/i,
    title: "TOR/Anonymous Network Traffic",
    description: "Network traffic associated with TOR exit nodes or anonymous overlay networks.",
    severity: "high",
    mitreTactic: "Command and Control",
    mitreTechnique: "T1090.003 - Multi-hop Proxy",
  },
  {
    pattern: /dns.*tunnel|dns.*exfil|txt.*record.*(?:base64|encoded)|unusually.*long.*dns|nslookup.*-type=txt/i,
    title: "DNS Tunneling Detected",
    description: "DNS queries exhibiting characteristics of DNS tunneling for data exfiltration.",
    severity: "high",
    mitreTactic: "Exfiltration",
    mitreTechnique: "T1048.001 - Exfiltration Over Alternative Protocol",
  },
  {
    pattern: /powershell.*(?:-enc|-encoded|downloadstring|invoke-expression|iex|bypass|hidden|noprofile)|pwsh.*-e\s/i,
    title: "Suspicious PowerShell Execution",
    description: "PowerShell command with encoded, download, or execution bypass parameters detected.",
    severity: "high",
    mitreTactic: "Execution",
    mitreTechnique: "T1059.001 - PowerShell",
  },
  {
    pattern: /lateral.*movement|psexec|wmic.*process.*call|schtasks.*\/create.*\/s|winrm|evil-winrm/i,
    title: "Lateral Movement Detected",
    description: "Activity consistent with lateral movement between network hosts.",
    severity: "critical",
    mitreTactic: "Lateral Movement",
    mitreTechnique: "T1021 - Remote Services",
  },
  {
    pattern: /phish|spear.*phish|malicious.*attachment|suspicious.*link.*email|macro.*enabled/i,
    title: "Phishing Attempt Detected",
    description: "Email or communication exhibiting phishing characteristics.",
    severity: "medium",
    mitreTactic: "Initial Access",
    mitreTechnique: "T1566 - Phishing",
  },
  {
    pattern: /privilege.*escalat|sudo.*(?:exploit|vuln)|suid.*binary|setuid|kernel.*exploit|local.*root/i,
    title: "Privilege Escalation Attempt",
    description: "Activity suggesting attempt to escalate privileges on the system.",
    severity: "critical",
    mitreTactic: "Privilege Escalation",
    mitreTechnique: "T1068 - Exploitation for Privilege Escalation",
  },
  {
    pattern: /data.*exfil|large.*upload|unusual.*outbound|bulk.*transfer|upload.*external/i,
    title: "Data Exfiltration Suspected",
    description: "Unusual outbound data transfer patterns suggesting data exfiltration.",
    severity: "high",
    mitreTactic: "Exfiltration",
    mitreTechnique: "T1041 - Exfiltration Over C2 Channel",
  },
  {
    pattern: /ransomware|encrypt.*files|ransom.*note|\.locked|\.encrypted|bitcoin.*payment/i,
    title: "Ransomware Activity Detected",
    description: "File encryption patterns or ransomware indicators observed.",
    severity: "critical",
    mitreTactic: "Impact",
    mitreTechnique: "T1486 - Data Encrypted for Impact",
  },
  {
    pattern: /port.*scan|nmap|masscan|syn.*scan|service.*enumerat|reconnaissance/i,
    title: "Network Reconnaissance Detected",
    description: "Port scanning or network reconnaissance activity detected.",
    severity: "medium",
    mitreTactic: "Reconnaissance",
    mitreTechnique: "T1046 - Network Service Discovery",
  },
  {
    pattern: /webshell|web.*shell|cmd\.php|c99|r57|china.*chopper|eval\s*\(\s*\$_(POST|GET|REQUEST)/i,
    title: "Web Shell Detected",
    description: "Web shell deployment or access detected on web server.",
    severity: "critical",
    mitreTactic: "Persistence",
    mitreTechnique: "T1505.003 - Web Shell",
  },
  {
    pattern: /malware|trojan|virus|worm|backdoor|rootkit|keylogger|spyware/i,
    title: "Malware Indicator Detected",
    description: "Content matches known malware signatures or indicators.",
    severity: "high",
    mitreTactic: "Execution",
    mitreTechnique: "T1204 - User Execution",
  },
]

export function classifyLog(message: string, source?: string): ClassificationResult | null {
  const fullText = source ? `${source} ${message}` : message

  for (const rule of detectionRules) {
    if (rule.pattern.test(fullText)) {
      return {
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        mitreTactic: rule.mitreTactic,
        mitreTechnique: rule.mitreTechnique,
      }
    }
  }

  return null
}

export function shouldGenerateAlert(severity: Severity): boolean {
  return severity === "critical" || severity === "high"
}
