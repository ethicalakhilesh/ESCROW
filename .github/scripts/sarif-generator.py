import json

with open('report.json') as f:
    baseline = json.load(f)

sarif = {
    "version": "2.1.0",
    "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "detect-secrets"
                }
            },
            "results": []
        }
    ]
}

for finding in baseline["results"]:
    filename = finding["filename"]
    secret = finding["secrets"]
    level = "warning"

    for line_str, line_content in finding["lines"].items():
        line_number = int(line_str)
        start_column = line_content.find(secret) + 1
        end_column = start_column + len(secret)

        for rule_id in finding["types"]:
            sarif_result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Potential secret found: {rule_id}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": filename
                            },
                            "region": {
                                "startLine": line_number,
                                "endLine": line_number,
                                "startColumn": start_column,
                                "endColumn": end_column
                            }
                        }
                    }
                ]
            }

            sarif["runs"][0]["results"].append(sarif_result)

with open('results.sarif', 'w') as f:
    json.dump(sarif, f, indent=4)
