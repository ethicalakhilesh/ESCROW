import json
import copy

def find_secret_indices(input_json_file, output_json_file, template_file):
    try:
        with open(template_file, 'r') as tmpl_file:
            sarif_template = json.load(tmpl_file)
            format_template = sarif_template["result"]
            sarif_wrapper = sarif_template["wrapper"]

        with open(input_json_file, 'r') as file:
            data = json.load(file)

        results = []

        for entry in data["results"]:
            filename = entry["filename"]
            secret = entry["secrets"]
            types = entry["types"]

            try:
                with open(filename, 'r') as f:
                    for line_number, line in enumerate(f, start=1):
                        start_index = line.find(secret)
                        if start_index != -1:
                            start_index = start_index + 1  # Make 1-based index
                            end_index = start_index + len(secret) - 1

                            for rule_type in types:
                                result_entry = copy.deepcopy(format_template)
                                result_entry["ruleId"] = rule_type
                                result_entry["message"]["text"] = rule_type
                                result_entry["message"]["markdown"] = rule_type
                                result_entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = filename
                                result_entry["locations"][0]["physicalLocation"]["region"]["startLine"] = line_number
                                result_entry["locations"][0]["physicalLocation"]["region"]["startColumn"] = start_index
                                result_entry["locations"][0]["physicalLocation"]["region"]["endLine"] = line_number
                                result_entry["locations"][0]["physicalLocation"]["region"]["endColumn"] = end_index

                                results.append(result_entry)

            except FileNotFoundError:
                print(f"Error: File '{filename}' not found.")
            except Exception as e:
                print(f"An error occurred while processing '{filename}': {e}")

        # Inject results into SARIF wrapper
        sarif_wrapper["runs"][0]["results"] = results

        with open(output_json_file, 'w') as out_file:
            json.dump(sarif_wrapper, out_file, indent=4)
        print(f"Results saved to '{output_json_file}'.")

    except Exception as e:
        print(f"Error processing JSON file: {e}")

# Example usage
input_json_file = "report.json"
output_json_file = "secrets.sarif"
template_file = "./.github/scripts/sarif-template.json"

find_secret_indices(input_json_file, output_json_file, template_file)
