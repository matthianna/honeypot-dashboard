"""MITRE ATT&CK detection and mapping service."""

from typing import Dict, List, Any, Set
import re

# MITRE ATT&CK Technique Definitions with severity and references
MITRE_TECHNIQUES = {
    # ==================== Reconnaissance ====================
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries scan victim IP blocks to gather information that can be used during targeting",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    "T1595.001": {
        "id": "T1595.001",
        "name": "Scanning IP Blocks",
        "tactic": "Reconnaissance",
        "description": "Scan IP blocks to identify active hosts and services",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1595/001/",
    },
    "T1595.002": {
        "id": "T1595.002",
        "name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": "Scan for vulnerabilities in target systems",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1595/002/",
    },
    "T1592": {
        "id": "T1592",
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": "Gather information about victim hosts that can be used during targeting",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1592/",
    },
    "T1589": {
        "id": "T1589",
        "name": "Gather Victim Identity Info",
        "tactic": "Reconnaissance",
        "description": "Gather credentials or other identity information",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1589/",
    },
    
    # ==================== Initial Access ====================
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploit vulnerabilities in internet-facing systems to gain access",
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1133": {
        "id": "T1133",
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Leverage external-facing remote services like VPNs, Citrix, RDP",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1133/",
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Obtain and abuse credentials of existing accounts",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    
    # ==================== Execution ====================
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Abuse command and script interpreters to execute commands",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Abuse PowerShell to execute commands or scripts",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.004": {
        "id": "T1059.004",
        "name": "Unix Shell",
        "tactic": "Execution",
        "description": "Abuse Unix shell to execute commands or scripts",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
    },
    "T1059.006": {
        "id": "T1059.006",
        "name": "Python",
        "tactic": "Execution",
        "description": "Abuse Python interpreter to execute commands",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1059/006/",
    },
    "T1203": {
        "id": "T1203",
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Exploit software vulnerabilities in client applications",
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1203/",
    },
    
    # ==================== Persistence ====================
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Manipulate accounts to maintain access",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1136": {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Create a local or domain account for persistence",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1136/",
    },
    "T1053": {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Abuse task scheduling for persistence or execution",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    "T1053.003": {
        "id": "T1053.003",
        "name": "Cron",
        "tactic": "Persistence",
        "description": "Abuse cron for persistence or execution",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1053/003/",
    },
    "T1505.003": {
        "id": "T1505.003",
        "name": "Web Shell",
        "tactic": "Persistence",
        "description": "Use web shells for persistence and command execution",
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
    },
    
    # ==================== Privilege Escalation ====================
    "T1068": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Exploit software vulnerability to escalate privileges",
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Bypass mechanisms designed to control elevated privileges",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "T1548.003": {
        "id": "T1548.003",
        "name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "description": "Abuse sudo privileges or cached credentials",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    
    # ==================== Defense Evasion ====================
    "T1070": {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Delete or modify artifacts to remove evidence",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1070/",
    },
    "T1070.003": {
        "id": "T1070.003",
        "name": "Clear Command History",
        "tactic": "Defense Evasion",
        "description": "Clear command history to hide malicious activity",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1070/003/",
    },
    "T1070.004": {
        "id": "T1070.004",
        "name": "File Deletion",
        "tactic": "Defense Evasion",
        "description": "Delete files to remove evidence",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1070/004/",
    },
    "T1562": {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Disable security tools and defenses",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1562/",
    },
    "T1562.001": {
        "id": "T1562.001",
        "name": "Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Disable or modify security software",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
    
    # ==================== Credential Access ====================
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Use brute force techniques to attempt access to accounts",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Guess passwords to attempt authentication",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1110.002": {
        "id": "T1110.002",
        "name": "Password Cracking",
        "tactic": "Credential Access",
        "description": "Crack password hashes offline",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1110/002/",
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": "Use one password against many accounts",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "T1110.004": {
        "id": "T1110.004",
        "name": "Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Use stolen credentials from breaches",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1110/004/",
    },
    "T1552": {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Search for insecurely stored credentials",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1552.001": {
        "id": "T1552.001",
        "name": "Credentials In Files",
        "tactic": "Credential Access",
        "description": "Search local file systems for credentials",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
    },
    
    # ==================== Discovery ====================
    "T1082": {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Get detailed information about the operating system and hardware",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    "T1083": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Enumerate files and directories on file systems",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Get a listing of services running on remote hosts",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1018": {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Get a listing of other systems on the network",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    "T1049": {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": "Attempt to get listing of network connections",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1049/",
    },
    "T1016": {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Look for details about network configuration",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1016/",
    },
    "T1057": {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Get information about running processes",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1057/",
    },
    "T1007": {
        "id": "T1007",
        "name": "System Service Discovery",
        "tactic": "Discovery",
        "description": "Get information about registered services",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1007/",
    },
    "T1033": {
        "id": "T1033",
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "description": "Identify the primary user or owner of the system",
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1033/",
    },
    
    # ==================== Lateral Movement ====================
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Use remote services to move within network",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    "T1021.001": {
        "id": "T1021.001",
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Use RDP to move within network",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    },
    "T1021.002": {
        "id": "T1021.002",
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Use SMB to move within network",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    "T1021.004": {
        "id": "T1021.004",
        "name": "SSH",
        "tactic": "Lateral Movement",
        "description": "Use SSH to move within network",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1021/004/",
    },
    
    # ==================== Collection ====================
    "T1005": {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Search local system sources for data of interest",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1005/",
    },
    "T1119": {
        "id": "T1119",
        "name": "Automated Collection",
        "tactic": "Collection",
        "description": "Use automated techniques for collection",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1119/",
    },
    "T1560": {
        "id": "T1560",
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": "Compress or encrypt collected data prior to exfil",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1560/",
    },
    
    # ==================== Command and Control ====================
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Communicate using application layer protocols",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Communicate using HTTP/HTTPS",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1571": {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "Use non-standard ports for communication",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1571/",
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Transfer tools or files from external system",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    
    # ==================== Exfiltration ====================
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Steal data using a different protocol than C2",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Steal data by sending it over the C2 channel",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    
    # ==================== Impact ====================
    "T1485": {
        "id": "T1485",
        "name": "Data Destruction",
        "tactic": "Impact",
        "description": "Destroy data and files on specific systems",
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1485/",
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Encrypt data on target systems (ransomware)",
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "T1489": {
        "id": "T1489",
        "name": "Service Stop",
        "tactic": "Impact",
        "description": "Stop or disable services",
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1489/",
    },
    "T1496": {
        "id": "T1496",
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": "Leverage resources for cryptocurrency mining",
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1496/",
    },
}

# Enhanced command patterns for MITRE technique detection
COMMAND_PATTERNS = {
    # Reconnaissance & Discovery
    "T1082": [  # System Information Discovery
        r"\buname\b", r"\bhostname\b", r"\bhostnamectl\b", r"cat\s+/etc/os-release",
        r"cat\s+/proc/version", r"cat\s+/etc/issue", r"\blsb_release\b", r"\barch\b",
        r"cat\s+/proc/cpuinfo", r"cat\s+/proc/meminfo", r"\bdf\b", r"\bfree\b",
        r"\buptime\b", r"\bw\b", r"\blast\b", r"\bdmesg\b", r"\blscpu\b",
    ],
    "T1083": [  # File and Directory Discovery
        r"\bls\b", r"\bfind\b", r"\blocate\b", r"\bdir\b", r"\btree\b",
        r"cat\s+/etc/passwd", r"cat\s+/etc/shadow", r"cat\s+/etc/group",
        r"\bwhereis\b", r"\bwhich\b", r"\bfile\b",
    ],
    "T1018": [  # Remote System Discovery
        r"\bping\b", r"\barp\b", r"\bnmap\b", r"\bnetstat\b", r"\bss\b",
        r"ip\s+neigh", r"cat\s+/etc/hosts", r"\bhost\b", r"\bnslookup\b", 
        r"\bdig\b", r"\btraceroute\b", r"\btracepath\b",
    ],
    "T1049": [  # System Network Connections Discovery
        r"\bnetstat\b", r"\bss\b", r"lsof\s+-i", r"\bsockstat\b",
    ],
    "T1016": [  # System Network Configuration Discovery
        r"\bifconfig\b", r"ip\s+addr", r"ip\s+a\b", r"ip\s+route", r"ip\s+r\b",
        r"cat\s+/etc/resolv.conf", r"\broute\b", r"\bnetplan\b",
    ],
    "T1057": [  # Process Discovery
        r"\bps\b", r"\btop\b", r"\bhtop\b", r"\bpgrep\b", r"\bpidof\b",
        r"cat\s+/proc/\d+", r"\bpstree\b",
    ],
    "T1007": [  # System Service Discovery
        r"\bsystemctl\b", r"\bservice\b", r"\bchkconfig\b", r"\binitctl\b",
        r"ls\s+/etc/init.d", r"ls\s+/etc/systemd",
    ],
    "T1033": [  # System Owner/User Discovery
        r"\bwhoami\b", r"\bid\b", r"\busers\b", r"\bwho\b", r"\bgroups\b",
        r"cat\s+/etc/passwd", r"\blast\b", r"\bfinger\b",
    ],
    
    # Execution
    "T1059.004": [  # Unix Shell
        r"\bsh\b", r"\bbash\b", r"\bzsh\b", r"\bksh\b", r"\bcsh\b",
        r"/bin/sh\b", r"/bin/bash\b", r"\bexec\b",
    ],
    "T1059.006": [  # Python
        r"\bpython\b", r"\bpython3\b", r"\bpython2\b", r"\.py\b",
    ],
    "T1059.001": [  # PowerShell
        r"\bpowershell\b", r"\bpwsh\b", r"\.ps1\b",
    ],
    
    # Persistence
    "T1053.003": [  # Cron
        r"\bcrontab\b", r"cat\s+/etc/cron", r"/var/spool/cron",
        r"echo\s+.*>>\s*/etc/cron", r"\bat\b", r"\batq\b",
    ],
    "T1098": [  # Account Manipulation
        r"\busermod\b", r"\bchage\b", r"\bpasswd\b", r"echo\s+.*>>\s*/etc/passwd",
        r"echo\s+.*>>\s*/etc/shadow",
    ],
    "T1136": [  # Create Account
        r"\buseradd\b", r"\badduser\b", r"echo\s+.*>>\s*/etc/passwd",
    ],
    
    # Privilege Escalation
    "T1548.003": [  # Sudo and Sudo Caching
        r"\bsudo\b", r"cat\s+/etc/sudoers", r"\bvisudo\b",
    ],
    
    # Defense Evasion
    "T1070.003": [  # Clear Command History
        r"history\s+-c", r"unset\s+HISTFILE", r"export\s+HISTSIZE=0",
        r"rm\s+.*\.bash_history", r"cat\s+/dev/null\s*>\s*.*history",
    ],
    "T1070.004": [  # File Deletion
        r"\brm\s+-rf", r"\bshred\b", r"\bwipe\b", r"\bsrm\b",
    ],
    "T1562.001": [  # Disable or Modify Tools
        r"systemctl\s+(stop|disable)\s+(iptables|firewalld|ufw)",
        r"service\s+(iptables|firewalld)\s+stop", r"\bufw\s+disable\b",
        r"iptables\s+-F", r"setenforce\s+0",
    ],
    
    # Credential Access
    "T1552.001": [  # Credentials In Files
        r"cat\s+.*\.ssh", r"cat\s+.*\.gnupg", r"cat\s+.*\.pgpass",
        r"cat\s+.*\.my.cnf", r"cat\s+.*\.netrc", r"cat\s+.*\.aws",
        r"find\s+.*-name\s+.*pass", r"grep\s+.*password",
    ],
    
    # Collection
    "T1005": [  # Data from Local System
        r"\bcat\b", r"\bhead\b", r"\btail\b", r"\bless\b", r"\bmore\b",
        r"\bgrep\b", r"\bawk\b", r"\bsed\b", r"\bcut\b",
    ],
    "T1560": [  # Archive Collected Data
        r"\btar\b", r"\bgzip\b", r"\bzip\b", r"\brar\b", r"\b7z\b",
        r"\bbzip2\b", r"\bxz\b",
    ],
    
    # Command and Control / Exfiltration
    "T1105": [  # Ingress Tool Transfer
        r"\bwget\b", r"\bcurl\b", r"\bscp\b", r"\bsftp\b", r"\bftp\b",
        r"\btftp\b", r"\brsync\b", r"\bgit\s+clone\b",
    ],
    "T1048": [  # Exfiltration
        r"\bnc\b", r"\bnetcat\b", r"\bncat\b", r"\bsocat\b",
        r"\bbase64\b.*\|.*curl", r"\bcurl\b.*-d",
    ],
    
    # Impact
    "T1485": [  # Data Destruction
        r"rm\s+-rf\s+/", r"\bdd\s+if=/dev/(zero|urandom)", r"\bmkfs\b",
        r"shred\s+.*-u",
    ],
    "T1489": [  # Service Stop
        r"systemctl\s+stop", r"service\s+.*\s+stop", r"kill\s+-9",
        r"\bkillall\b", r"\bpkill\b",
    ],
    "T1496": [  # Resource Hijacking (Cryptomining)
        r"\bxmrig\b", r"\bcgminer\b", r"\bminerd\b", r"\bstratum\b",
        r"pool\.[a-z]+\.[a-z]+", r"\bmonero\b", r"\bcoin.*mine\b",
    ],
}

# Tactics order for display (kill chain order)
TACTICS_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Severity colors and weights
SEVERITY_CONFIG = {
    "critical": {"color": "#ff0000", "weight": 4},
    "high": {"color": "#ff6600", "weight": 3},
    "medium": {"color": "#ffcc00", "weight": 2},
    "low": {"color": "#39ff14", "weight": 1},
}


def get_technique(technique_id: str) -> Dict[str, Any]:
    """Get technique details by ID."""
    return MITRE_TECHNIQUES.get(technique_id, {})


def get_all_techniques() -> List[Dict[str, Any]]:
    """Get all defined techniques."""
    return list(MITRE_TECHNIQUES.values())


def get_techniques_by_tactic(tactic: str) -> List[Dict[str, Any]]:
    """Get techniques for a specific tactic."""
    return [t for t in MITRE_TECHNIQUES.values() if t["tactic"] == tactic]


def get_tactic_technique_matrix() -> Dict[str, List[Dict[str, Any]]]:
    """Get techniques organized by tactic for matrix display."""
    matrix = {tactic: [] for tactic in TACTICS_ORDER}
    for tech in MITRE_TECHNIQUES.values():
        tactic = tech["tactic"]
        if tactic in matrix:
            matrix[tactic].append(tech)
    return matrix


def detect_command_techniques(command: str) -> List[str]:
    """
    Detect MITRE techniques from a command string using regex patterns.
    Returns list of technique IDs.
    """
    detected: Set[str] = set()
    
    for technique_id, patterns in COMMAND_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, command, re.IGNORECASE):
                detected.add(technique_id)
                break
    
    return list(detected)


def categorize_command(command: str) -> Dict[str, Any]:
    """
    Categorize a command and return MITRE mappings with severity.
    """
    techniques = detect_command_techniques(command)
    
    # Get technique details
    technique_details = []
    max_severity = "low"
    severity_weight = 0
    
    for tech_id in techniques:
        if tech_id in MITRE_TECHNIQUES:
            tech = MITRE_TECHNIQUES[tech_id]
            technique_details.append(tech)
            tech_severity = tech.get("severity", "low")
            if SEVERITY_CONFIG[tech_severity]["weight"] > severity_weight:
                max_severity = tech_severity
                severity_weight = SEVERITY_CONFIG[tech_severity]["weight"]
    
    # Determine categories
    categories = set()
    for tech in technique_details:
        categories.add(tech["tactic"])
    
    if not categories:
        categories.add("Other")
    
    return {
        "command": command,
        "techniques": techniques,
        "categories": list(categories),
        "technique_details": technique_details,
        "severity": max_severity,
        "severity_color": SEVERITY_CONFIG[max_severity]["color"],
    }


def get_honeypot_technique_mapping() -> Dict[str, List[str]]:
    """
    Return mapping of honeypots to MITRE techniques they can detect.
    """
    return {
        "cowrie": [
            "T1110", "T1110.001", "T1110.003", "T1110.004",  # Brute Force
            "T1078",  # Valid Accounts
            "T1059.004", "T1059.006",  # Shell/Python
            "T1082", "T1083", "T1018", "T1049", "T1016", "T1057", "T1033",  # Discovery
            "T1005", "T1560",  # Collection
            "T1021.004",  # SSH
            "T1048", "T1105",  # Exfil/Transfer
            "T1053.003", "T1098", "T1136",  # Persistence
            "T1070.003", "T1070.004",  # Defense Evasion
            "T1548.003",  # Priv Esc
            "T1552.001",  # Credential Access
            "T1485", "T1489", "T1496",  # Impact
        ],
        "galah": [
            "T1190",  # Exploit Public-Facing App
            "T1595", "T1595.001", "T1595.002",  # Active Scanning
            "T1592",  # Gather Host Info
            "T1071", "T1071.001",  # Application Layer Protocol
            "T1203",  # Client Execution
            "T1505.003",  # Web Shell
        ],
        "dionaea": [
            "T1190",  # Exploit Public-Facing App
            "T1133",  # External Remote Services
            "T1571",  # Non-Standard Port
            "T1203",  # Client Execution
        ],
        "heralding": [
            "T1110", "T1110.001", "T1110.003",  # Brute Force
            "T1078",  # Valid Accounts
            "T1133",  # External Remote Services
            "T1589",  # Gather Victim Identity
        ],
        "rdpy": [
            "T1110", "T1110.001",  # Brute Force
            "T1021.001",  # RDP
            "T1078",  # Valid Accounts
        ],
        "firewall": [
            "T1046",  # Network Service Discovery
            "T1595", "T1595.001", "T1595.002",  # Active Scanning
            "T1571",  # Non-Standard Port
        ],
    }


def calculate_threat_score(techniques: List[str]) -> Dict[str, Any]:
    """
    Calculate an overall threat score based on detected techniques.
    """
    if not techniques:
        return {"score": 0, "level": "none", "color": "#888888"}
    
    total_weight = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for tech_id in techniques:
        if tech_id in MITRE_TECHNIQUES:
            severity = MITRE_TECHNIQUES[tech_id].get("severity", "low")
            severity_counts[severity] += 1
            total_weight += SEVERITY_CONFIG[severity]["weight"]
    
    # Normalize score to 0-100
    max_possible = len(techniques) * 4  # Max severity weight
    score = min(100, int((total_weight / max_possible) * 100)) if max_possible > 0 else 0
    
    # Determine level
    if severity_counts["critical"] > 0 or score >= 75:
        level = "critical"
    elif severity_counts["high"] > 0 or score >= 50:
        level = "high"
    elif severity_counts["medium"] > 0 or score >= 25:
        level = "medium"
    else:
        level = "low"
    
    return {
        "score": score,
        "level": level,
        "color": SEVERITY_CONFIG[level]["color"],
        "breakdown": severity_counts,
    }
