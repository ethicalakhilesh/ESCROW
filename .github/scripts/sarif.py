import json
import uuid
from datetime import datetime

def convert_to_sarif(input_json):
    # Define the SARIF 2.1.0 structure
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.2.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecretScanner",
                        "version": "1.0",
                        "rules": []  # Rules will be populated dynamically if needed
                    }
                },
                "results": []
            }
        ]
    }

    # Process the input JSON
    for result in input_json.get('results', []):
        # Each result maps to a SARIF result
        sarif_result = {
            "ruleId": "SecretFound",
            "ruleIndex": 0,
            "message": {
                "text": f"Secret detected: {result.get('secrets', '')}"
            },
            "locations": [],
            "partialFingerprints": {
                "primaryLocation": str(uuid.uuid4())
            }
        }
        
        # Parse lines with secrets
        for line_number, line_text in result.get("lines", {}).items():
            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": result.get("filename", "")
                    },
                    "region": {
                        "startLine": int(line_number),
                        "snippet": {
                            "text": line_text
                        }
                    }
                }
            }
            sarif_result["locations"].append(location)

        # Append this result to SARIF results
        sarif["runs"][0]["results"].append(sarif_result)

    return sarif

def save_sarif(sarif_data, output_file):
    with open(output_file, 'w') as f:
        json.dump(sarif_data, f, indent=4)

def load_json_from_file(input_file):
    with open(input_file, 'r') as f:
        return json.load(f)

# Input and output file paths
input_file = "report.json"  # Your input JSON file
output_file = "report.sarif"  # The output SARIF file

# Load the input JSON data from the file
input_json = load_json_from_file(input_file)

# Convert the input JSON to SARIF 2.1.0 format
sarif_data = convert_to_sarif(input_json)

# Save SARIF data to a file
save_sarif(sarif_data, output_file)

print(f"SARIF data saved to {output_file}")
