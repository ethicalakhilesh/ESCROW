import json
import hashlib

BLOCK_SIZE = 20

def normalize_line(line):
    return line.replace('\r\n', '\n').replace('\r', '\n')

def compute_rolling_hash(line):
    cleaned = ''.join(c for c in line if c not in (' ', '\t'))
    block = cleaned[:BLOCK_SIZE].ljust(BLOCK_SIZE, '\0')
    return hashlib.sha256(block.encode('utf-8')).hexdigest()

def find_secret_indices(input_json_file, output_json_file, template_file):
    try:
        with open(template_file, 'r') as tmpl_file:
            sarif_template = json.load(tmpl_file)
            sarif_wrapper = sarif_template["runs"][0]

        with open(input_json_file, 'r') as file:
            data = json.load(file)

        results = []

        for entry in data["results"]:
            filename = entry["filename"]
            secret = entry["secrets"]
            types = entry["types"]

            try:
                with open(filename, 'r') as f:
                    lines = f.readlines()
                    for line_number, line in enumerate(lines, start=1):
                        normalized_line = normalize_line(line)
                        start_index = normalized_line.find(secret)
                        if start_index != -1:
                            start_index = start_index + 1  # Make 1-based index
                            end_index = start_index + len(secret) - 1

                            hash_value = compute_rolling_hash(normalized_line)

                            for rule_type in types:
                                result_entry = {
                                    "ruleId": rule_type,
                                    "level": "error",
                                    "message": {
                                        "text": rule_type,
                                        "markdown": rule_type
                                    },
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": filename
                                                },
                                                "region": {
                                                    "startLine": line_number,
                                                    "startColumn": start_index,
                                                    "endLine": line_number,
                                                    "endColumn": end_index
                                                }
                                            }
                                        }
                                    ],
                                    "partialFingerprints": {
                                        "secret/v1": hash_value
                                    }
                                }

                                results.append(result_entry)

            except FileNotFoundError:
                print(f"Error: File '{filename}' not found.")
            except Exception as e:
                print(f"An error occurred while processing '{filename}': {e}")

        sarif_wrapper["results"] = results

        with open(output_json_file, 'w') as out_file:
            json.dump(sarif_template, out_file, indent=4)
        print(f"Results saved to '{output_json_file}'.")

    except Exception as e:
        print(f"Error processing JSON file: {e}")

# Example usage
input_json_file = "report.json"
output_json_file = "results.sarif"
template_file = "./.github/scripts/sarif-template.json"

find_secret_indices(input_json_file, output_json_file, template_file)
