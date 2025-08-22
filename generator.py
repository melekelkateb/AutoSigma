import yaml
from datetime import datetime
import argparse
attack_patterns = {
    "base64 powershell": {
        "title": "Suspicious PowerShell Base64 Execution",
        "description": "Detects PowerShell commands using base64 encoding",
        "level": "high",
        "selection": {"CommandLine|contains": ["-enc", "-EncodedCommand"]},
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.execution"]
    },
    "failed login": {
        "title": "Multiple Failed Login Attempts",
        "description": "Detects repeated failed login attempts",
        "level": "medium",
        "selection": {"EventID": 4625},
        "logsource": {"category": "authentication", "product": "windows"},
        "tags": ["attack.persistence"]
    },
    "new admin account": {
        "title": "Suspicious Admin Account Creation",
        "description": "Detects creation of new admin accounts",
        "level": "high",
        "selection": {"EventID": 4720},
        "logsource": {"category": "account_management", "product": "windows"},
        "tags": ["attack.persistence"]
    },
    "ransomware": {
        "title": "Potential Ransomware Execution",
        "description": "Detects ransomware-like file encryption behavior",
        "level": "critical",
        "selection": {"ProcessName|contains": ["vssadmin.exe", "encryptor.exe"]},
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.execution"]
    },
    "powershell download": {
        "title": "Suspicious PowerShell Download",
        "description": "Detects PowerShell downloading files from internet",
        "level": "high",
        "selection": {"CommandLine|contains": ["Invoke-WebRequest", "wget", "curl"]},
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.execution"]
    },
    "lateral movement": {
        "title": "Suspicious Lateral Movement",
        "description": "Detects potential lateral movement using admin shares",
        "level": "high",
        "selection": {"CommandLine|contains": ["\\\\ADMIN$", "net use"]},
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.lateral_movement"]
    },
    "wmic process": {
        "title": "Suspicious WMIC Process Creation",
        "description": "Detects unusual use of WMIC for process execution",
        "level": "medium",
        "selection": {"CommandLine|contains": ["wmic process call create"]},
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.execution"]
    },
    "cmd download": {
        "title": "Suspicious CMD Download",
        "description": "Detects file download via CMD (bitsadmin, certutil)",
        "level": "medium",
        "selection": {"CommandLine|contains": ["bitsadmin", "certutil"]},
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.execution"]
    },
    "suspicious service": {
        "title": "Suspicious Service Creation",
        "description": "Detects creation of unusual Windows services",
        "level": "high",
        "selection": {"EventID": 7045},
        "logsource": {"category": "system", "product": "windows"},
        "tags": ["attack.persistence"]
    },
    "mimikatz": {
        "title": "Mimikatz Execution Detected",
        "description": "Detects execution of credential dumping tools like Mimikatz",
        "level": "critical",
        "selection": {"ProcessName|contains": ["mimikatz.exe"]},
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.credential_access"]
    },
    "unauthorized usb": {
        "title": "Unauthorized USB Device Connected",
        "description": "Detects new USB storage devices connected",
        "level": "medium",
        "selection": {"EventID": 2003},
        "logsource": {"category": "device", "product": "windows"},
        "tags": ["attack.persistence"]
    },
    "registry modification": {
        "title": "Suspicious Registry Modification",
        "description": "Detects changes to sensitive registry keys",
        "level": "high",
        "selection": {"EventID": 4657},
        "logsource": {"category": "registry", "product": "windows"},
        "tags": ["attack.persistence"]
    },
    "suspicious scheduled task": {
        "title": "Suspicious Scheduled Task",
        "description": "Detects creation of suspicious scheduled tasks",
        "level": "high",
        "selection": {"EventID": 4698},
        "logsource": {"category": "task", "product": "windows"},
        "tags": ["attack.persistence"]
    },
    "powershell download crl": {
        "title": "PowerShell Downloading from CRL URL",
        "description": "Detects PowerShell downloading from unusual URLs",
        "level": "high",
        "selection": {"CommandLine|contains": ["-URL", "-OutFile"]},
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.execution"]}}
def generate_sigma(description: str) -> str:
    description_lower = description.lower()
    
    for key, rule in attack_patterns.items():
        if all(word in description_lower for word in key.split()):
            sigma_rule = {
                "title": rule["title"],
                "description": rule["description"],
                "status": "experimental",
                "author": "SOC Analyst",
                "date":datetime.now().strftime("%Y-%m-%d"),
                "logsource": rule["logsource"],
                "detection": {
                    "selection": rule["selection"],
                    "condition": "selection"
                },
                "level": rule["level"],
                "tags": rule["tags"]
            }
            return yaml.safe_dump(sigma_rule, sort_keys=False)
    return "No matching rule found."
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, required=True, help="Plain description of detection idea")
    args = parser.parse_args()
    rule = generate_sigma(args.input)
    print(rule)