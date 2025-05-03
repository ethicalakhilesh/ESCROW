import json
import hashlib

BLOCK_SIZE = 64

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
                file_hashes = hash_file_contents(filename)

                with open(filename, 'r') as f:
                    for line_number, line in enumerate(f, start=1):
                        start_index = line.find(secret)
                        if start_index != -1:
                            start_index = start_index + 1  # Make 1-based index
                            end_index = start_index + len(secret) - 1

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
                                        "secret/v1": file_hashes[line_number - 1] if line_number - 1 < len(file_hashes) else ""
                                    }
                                }

                                results.append(result_entry)

            except FileNotFoundError:
                print(f"Error: File '{filename}' not found.")
            except Exception as e:
                print(f"An error occurred while processing '{filename}': {e}")

        # Inject results into SARIF wrapper
        sarif_wrapper["results"] = results

        with open(output_json_file, 'w') as out_file:
            json.dump(sarif_template, out_file, indent=4)
        print(f"Results saved to '{output_json_file}'.")

    except Exception as e:
        print(f"Error processing JSON file: {e}")


def hash_file_contents(filename):
    hashes = []
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.read().replace('\r\n', '\n').replace('\r', '\n').split('\n')
            lines.append('-1')
            lines.extend(['\0'] * BLOCK_SIZE)

            for line in lines:
                normalized_line = ''.join(c for c in line if c not in [' ', '\t'])
                snippet = normalized_line[:BLOCK_SIZE].ljust(BLOCK_SIZE, '\0')
                line_hash = hashlib.sha256(snippet.encode('utf-8')).hexdigest()
                hashes.append(line_hash)
    except Exception as e:
        print(f"Failed to hash file '{filename}': {e}")
    return hashes

# Example usage
input_json_file = "report.json"
output_json_file = "secrets.sarif"
template_file = "./.github/scripts/sarif-template.json"

find_secret_indices(input_json_file, output_json_file, template_file)