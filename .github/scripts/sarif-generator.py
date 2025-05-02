import json

def find_secret_indices(input_json_file, output_json_file, format_json_file):
    try:
        with open(format_json_file, 'r') as fmt_file:
            format_template = json.load(fmt_file)

        with open(input_json_file, 'r') as file:
            data = json.load(file)

        output_results = []

        for entry in data["results"]:
            filename = entry["filename"]
            secret = entry["secrets"]
            types = entry["types"]

            try:
                with open(filename, 'r') as f:
                    for line_number, line in enumerate(f, start=1):
                        start_index = line.find(secret)
                        if start_index != -1:
                            start_index = start_index + 1  # Make it 1-based index
                            end_index = start_index + len(secret) - 1

                            for rule_type in types:
                                result_entry = format_template.copy()
                                result_entry["ruleId"] = rule_type
                                result_entry["message"]["text"] = rule_type
                                result_entry["message"]["markdown"] = rule_type
                                result_entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = filename
                                result_entry["locations"][0]["physicalLocation"]["region"]["startLine"] = line_number
                                result_entry["locations"][0]["physicalLocation"]["region"]["startColumn"] = start_index
                                result_entry["locations"][0]["physicalLocation"]["region"]["endLine"] = line_number
                                result_entry["locations"][0]["physicalLocation"]["region"]["endColumn"] = end_index

                                output_results.append(result_entry)

            except FileNotFoundError:
                print(f"Error: File '{filename}' not found.")
            except Exception as e:
                print(f"An error occurred while processing '{filename}': {e}")

        # Wrapping output_results under a custom JSON key
        final_output = f"""
        {
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "runs": [
            {
                "tool": {
                    "driver": {
                        "organization": "Yelp",
                        "name": "detect-secrets",
                        "informationUri": "https://github.com/Yelp/detect-secrets",
                        "version": "1.5.0"
                    }
                },
                "results": output_results  # Embedding output_results under "key3"
                }
            ]
        }"""
        # Save results to the output file
        with open(output_json_file, 'w') as out_file:
            json.dump(final_output, out_file, indent=4)
        print(f"Results saved to '{output_json_file}'.")

    except Exception as e:
        print(f"Error processing JSON file: {e}")

# Example usage
input_json_file = "report.json"
output_json_file = "secrets.sarif"
format_json_file = "./.github/scripts/sarif-format.json"

find_secret_indices(input_json_file, output_json_file, format_json_file)
