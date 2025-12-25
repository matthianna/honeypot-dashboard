"""MITRE ATT&CK detection and mapping service."""

from typing import Dict, List, Any

# MITRE ATT&CK Technique Definitions
MITRE_TECHNIQUES = {
    # Reconnaissance
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries scan victim IP blocks to gather information",
    },
    "T1595.002": {
        "id": "T1595.002",
        "name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": "Scan for vulnerabilities in target systems",
    },
    "T1592": {
        "id": "T1592",
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": "Gather information about victim hosts",
    },
    
    # Initial Access
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploit vulnerabilities in internet-facing systems",
    },
    "T1133": {
        "id": "T1133",
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Leverage external-facing remote services",
    },
    
    # Credential Access
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Use brute force techniques to attempt access",
    },
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Guess passwords to attempt authentication",
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": "Use one password against many accounts",
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Credential Access",
        "description": "Obtain and abuse credentials of existing accounts",
    },
    
    # Execution
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Abuse command and script interpreters to execute commands",
    },
    "T1059.004": {
        "id": "T1059.004",
        "name": "Unix Shell",
        "tactic": "Execution",
        "description": "Abuse Unix shell to execute commands",
    },
    
    # Discovery
    "T1082": {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Attempt to get detailed information about the operating system",
    },
    "T1083": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Enumerate files and directories",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Get a listing of services running on remote hosts",
    },
    "T1018": {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Attempt to get a listing of other systems on the network",
    },
    
    # Lateral Movement
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Use remote services to move within network",
    },
    "T1021.001": {
        "id": "T1021.001",
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Use RDP to move within network",
    },
    "T1021.004": {
        "id": "T1021.004",
        "name": "SSH",
        "tactic": "Lateral Movement",
        "description": "Use SSH to move within network",
    },
    
    # Collection
    "T1005": {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Search local system for data of interest",
    },
    
    # Command and Control
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Communicate using application layer protocols",
    },
    "T1571": {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "Use non-standard ports for communication",
    },
    
    # Exfiltration
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Steal data using a different protocol than command and control",
    },
}

# Command patterns for MITRE technique detection
COMMAND_PATTERNS = {
    "T1082": [  # System Information Discovery
        "uname", "hostname", "hostnamectl", "cat /etc/os-release",
        "cat /proc/version", "cat /etc/issue", "lsb_release", "arch",
        "cat /proc/cpuinfo", "cat /proc/meminfo", "df", "free",
        "uptime", "w", "last",
    ],
    "T1083": [  # File and Directory Discovery
        "ls", "find", "locate", "dir", "tree", "cat /etc/passwd",
        "cat /etc/shadow", "cat /etc/group",
    ],
    "T1018": [  # Remote System Discovery
        "ping", "arp", "nmap", "netstat", "ss", "ip neigh",
        "cat /etc/hosts", "host", "nslookup", "dig",
    ],
    "T1005": [  # Data from Local System
        "cat", "head", "tail", "less", "more", "grep",
        "find", "locate",
    ],
    "T1059.004": [  # Unix Shell
        "sh", "bash", "zsh", "ksh", "csh", "/bin/sh", "/bin/bash",
    ],
    "T1048": [  # Exfiltration
        "wget", "curl", "scp", "sftp", "ftp", "nc", "netcat",
        "tftp", "rsync",
    ],
}

# Tactics order for display
TACTICS_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Credential Access",
    "Execution",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
]


def get_technique(technique_id: str) -> Dict[str, Any]:
    """Get technique details by ID."""
    return MITRE_TECHNIQUES.get(technique_id, {})


def get_all_techniques() -> List[Dict[str, Any]]:
    """Get all defined techniques."""
    return list(MITRE_TECHNIQUES.values())


def get_techniques_by_tactic(tactic: str) -> List[Dict[str, Any]]:
    """Get techniques for a specific tactic."""
    return [t for t in MITRE_TECHNIQUES.values() if t["tactic"] == tactic]


def detect_command_techniques(command: str) -> List[str]:
    """
    Detect MITRE techniques from a command string.
    Returns list of technique IDs.
    """
    command_lower = command.lower()
    detected = set()
    
    for technique_id, patterns in COMMAND_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in command_lower:
                detected.add(technique_id)
                break
    
    return list(detected)


def categorize_command(command: str) -> Dict[str, Any]:
    """
    Categorize a command and return MITRE mappings.
    """
    techniques = detect_command_techniques(command)
    
    categories = []
    if any(t in techniques for t in ["T1082", "T1018"]):
        categories.append("Reconnaissance")
    if "T1083" in techniques or "T1005" in techniques:
        categories.append("Discovery")
    if "T1048" in techniques:
        categories.append("Download/Exfiltration")
    if "T1059.004" in techniques:
        categories.append("Execution")
    
    if not categories:
        categories.append("Other")
    
    return {
        "command": command,
        "techniques": techniques,
        "categories": categories,
        "technique_details": [MITRE_TECHNIQUES.get(t, {}) for t in techniques if t in MITRE_TECHNIQUES],
    }


def get_honeypot_technique_mapping() -> Dict[str, List[str]]:
    """
    Return mapping of honeypots to MITRE techniques they can detect.
    """
    return {
        "cowrie": [
            "T1110", "T1110.001", "T1110.003",  # Brute Force
            "T1078",  # Valid Accounts
            "T1059.004",  # Unix Shell
            "T1082", "T1083", "T1018",  # Discovery
            "T1005",  # Collection
            "T1021.004",  # SSH
            "T1048",  # Exfiltration
        ],
        "galah": [
            "T1190",  # Exploit Public-Facing App
            "T1595", "T1595.002",  # Active Scanning
            "T1592",  # Gather Host Info
            "T1071",  # Application Layer Protocol
        ],
        "dionaea": [
            "T1190",  # Exploit Public-Facing App
            "T1133",  # External Remote Services
            "T1571",  # Non-Standard Port
        ],
        "heralding": [
            "T1110", "T1110.001",  # Brute Force
            "T1078",  # Valid Accounts
            "T1133",  # External Remote Services
        ],
        "rdpy": [
            "T1110", "T1110.001",  # Brute Force
            "T1021.001",  # RDP
            "T1078",  # Valid Accounts
        ],
        "firewall": [
            "T1046",  # Network Service Discovery
            "T1595",  # Active Scanning
            "T1571",  # Non-Standard Port
        ],
    }




