import os
import yaml
import pandas as pd

# Recursive function to search for `name` and `width` in the YAML structure
def process_yaml_data(data):
    name_count = 0
    total_width = 0

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                # Recursively search in nested structures
                nested_count, nested_width = process_yaml_data(value)
                name_count += nested_count
                total_width += nested_width
            elif key == "name":
                name_count += 1
            elif key == "width":
                total_width += value

    elif isinstance(data, list):
        for item in data:
            # Recursively search in list items
            nested_count, nested_width = process_yaml_data(item)
            name_count += nested_count
            total_width += nested_width

    return name_count, total_width

# Function to process YAML file
def process_yaml_file(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)

    name_count, total_width = process_yaml_data(data)
    return name_count, total_width

# Main function to process files and create a DataFrame
def main(folders):
    file_data = []

    # Dictionary to map file names to custom labels
    file_name_mapping = {
        "registers_wop_1.yaml": "Baseline -- D-RI5CY",
        "registers_simple_parity_1.yaml": "Strategy Simple Parity 1",
        "registers_hamming_1.yaml": "Strategy Hamming code 1",
        "registers_hamming_2.yaml": "Strategy Hamming code 2",
        "registers_hamming_3.yaml": "Strategy Hamming code 3",
        "registers_hamming_4.yaml": "Strategy Hamming code 4",
        "registers_hamming_5.yaml": "Strategy Hamming code 5",
        "registers_secded_1.yaml": "Strategy SECDED code 1",
        "registers_secded_2.yaml": "Strategy SECDED code 2",
        "registers_secded_3.yaml": "Strategy SECDED code 3",
        "registers_secded_4.yaml": "Strategy SECDED code 4",
        "registers_secded_5.yaml": "Strategy SECDED code 5",
    }

    # Process YAML files in each folder
    for folder in folders:
        for file_name in os.listdir(folder):
            if file_name.endswith('.yaml') or file_name.endswith('.yml'):
                file_path = os.path.join(folder, file_name)
                name_count, total_width = process_yaml_file(file_path)
                
                # Use the mapped name if available, else use the original (capitalised) file name
                display_name = file_name_mapping.get(file_name, file_name)
                
                file_data.append({"Folder": folder.capitalize().replace("_", " "), "File": display_name, "Number of Registers": name_count, "Number of Bits": total_width})

    # Create a DataFrame
    df = pd.DataFrame(file_data)
    
    # Sort DataFrame by the "File" column to ensure correct strategy order
    df = df.sort_values(by="File")

    # Convert DataFrame to LaTeX
    latex_code = df.to_latex(index=False, caption="YAML File Summary", label="tab:yaml_summary")

    # Write LaTeX code to a file
    with open("yaml_summary_table.tex", "w") as latex_file:
        latex_file.write(latex_code)

    print("LaTeX table generated: yaml_summary_table.tex")

if __name__ == "__main__":
    # Specify the list of folders in the order you want to process
    folders = ["wop", "simple_parity", "hamming", "secded"]
    main(folders)
