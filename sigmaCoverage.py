"""
Creates an ATT&CK Navigator layer based on Sigma rule dump
Sigma rules dumped on 2022-05-06
"""
from mitreattack.navlayers import Layer
import os
import re

# Find number of rules per technique
rule_count_per_technique = {}
rules_per_technique = {}

for root, _, files in os.walk("rules"):
    for file in files:
        file_path = os.path.join(root, file)
        rule_name = file_path
        try:
            with open(file_path) as f:
                for line in f:
                    found_title = re.findall("title: (.*)", line)
                    if found_title:
                        rule_name = found_title[0]
                    
                    technique = re.findall("attack\.(t\d{4}(?:\.\d{3})?)", line)
                    if technique:
                        t = technique[0]
                        if t in rule_count_per_technique:
                            rule_count_per_technique[t] += 1
                            rules_per_technique[t].append(rule_name)
                        else:
                            rule_count_per_technique[t] = 1
                            rules_per_technique[t] = [rule_name]
                            

        except UnicodeDecodeError as e:
            continue

# Calculate Scores
for technique in rule_count_per_technique:
    print(technique, rule_count_per_technique[technique])

maximum_rule_count_key = max(rule_count_per_technique, key=rule_count_per_technique.get)
maximum_rule_count = float(rule_count_per_technique[maximum_rule_count_key])

scores = [{
    "techniqueID": technique.upper(), 
    "score": int((rule_count/maximum_rule_count) * 100),
    "comment": ", ".join(rules_per_technique[technique])
    } for technique, rule_count in rule_count_per_technique.items()]

example_layer4_dict = {
    "name": "Sigma Coverage",
    "versions" : {
        "attack": "11",
        "layer" : "4.3",
        "navigator": "4.3"
    },
    "domain": "enterprise-attack",
    "techniques": scores
}

layerA = Layer()
layerA.from_dict(example_layer4_dict)
layerA.to_file("sigma_coverage.json")
