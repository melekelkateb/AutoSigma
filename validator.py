def validate_rule(rule: str) -> bool:
    return "title:" in rule and "detection:" in rule and "logsource:" in rule
if __name__ == "__main__":
    sample_rule = open("examples/sigma_example.yaml").read()
    print("Valid:" if validate_rule(sample_rule) else "Invalid")