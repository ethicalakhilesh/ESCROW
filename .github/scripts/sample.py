import json

def find_secret_indices(input_json_file, output_json_file):
    try:
        with open(input_json_file, 'r') as file:
            data = json.load(file)

        output_results = []

        for entry in data["results"]:
            filename = entry["filename"]
            secret = entry["secrets"]

            try:
                with open(filename, 'r') as f:
                    for line_number, line in enumerate(f, start=1):
                        start_index = line.find(secret)
                        if start_index != -1:
                            end_index = start_index + len(secret) - 1
                            output_results.append({
                                "filename": filename,
                                "secrets": secret,
                                "region": {
                                    "startLine": line_number,
                                    "startColumn": start_index,
                                    "endLine": line_number,
                                    "endColumn": end_index
                                }
                            })
            except FileNotFoundError:
                print(f"Error: File '{filename}' not found.")
            except Exception as e:
                print(f"An error occurred while processing '{filename}': {e}")

        # Save results to the output file
        with open(output_json_file, 'w') as out_file:
            json.dump(output_results, out_file, indent=4)
        print(f"Results saved to '{output_json_file}'.")

    except Exception as e:
        print(f"Error processing JSON file: {e}")

# Example usage
input_json_file = "report.json"  # Replace with your actual JSON file
output_json_file = "alpha.json"  # Output file name
find_secret_indices(input_json_file, output_json_file)
