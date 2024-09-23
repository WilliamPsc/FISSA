import yaml
import pandas as pd

# Function to escape underscores in LaTeX
def escape_latex_special_chars(text):
    return text.replace("_", r"\_").replace("\[", r"[").replace("\]", r"]")

# Function to extract only the last part of the register name
def extract_last_part_of_name(full_name):
    return full_name.split("/")[-1]

# Recursive function to extract register information
def extract_registers(data, parent_module=None):
    registers = []

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                # If it's a list under a module, extract registers
                for item in value:
                    registers += extract_registers(item, parent_module=key)
            elif isinstance(value, dict):
                # If it's a dictionary, assume it's a module and recurse
                registers += extract_registers(value, parent_module=key)
            elif key == "name" and "width" in data:
                # Extract only the last part of the name and escape underscores
                register_name = escape_latex_special_chars(extract_last_part_of_name(value))
                # Add register info (last part of name, parent module, and width)
                registers.append({
                    "register_name": register_name,  # Only keep the last part of the name
                    "module": escape_latex_special_chars(parent_module),  # Escape underscores
                    "size": data["width"]
                })

    return registers

# Function to process the YAML file and generate the LaTeX table
def process_yaml_file(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)

    # Extract register information
    registers = extract_registers(data)

    # Create a DataFrame from the register information
    df = pd.DataFrame(registers)

    # Generate LaTeX table
    latex_code = df.to_latex(index=False, column_format='rcc', header=["Register Name", "Module", "Size"], 
                             caption="D-RI5CY Registers Information", label="tab:driscy_register_info", escape=False)

    # Write the LaTeX table to a file
    with open("registers_info_table.tex", "w") as latex_file:
        latex_file.write(latex_code)

    print("LaTeX table generated: registers_table.tex")

if __name__ == "__main__":
    # Specify the path to the YAML file
    file_path = "wop/registers_wop_1.yaml"
    process_yaml_file(file_path)
