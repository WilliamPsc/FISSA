<p align="center">
    <img src="https://img.shields.io/badge/language-Python3-%23f34b7d.svg?style=for-the-badge&logo=python" alt="Python3.10">
    <img src="https://img.shields.io/badge/tool-Fault_Injection_Attacks-red?style=for-the-badge&logo=framework" alt="tool">
    <img src="https://img.shields.io/badge/License-CeCILL--B-0078d7.svg?style=for-the-badge" alt="CeCILL-B">
    <br/>
    <img alt="GitHub commit activity" src="https://img.shields.io/github/commit-activity/t/WilliamPsc/FISSA?style=for-the-badge&logo=Github">
    <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/WilliamPsc/FISSA?display_timestamp=author&style=for-the-badge&logo=Github">
    <br/>
    <img alt="Static Badge" src="https://img.shields.io/badge/version-V1.0-blue?style=for-the-badge&logo=Github">
</p>

# FISSA: Fault Injection Simulation for Security Assessment
## Building Fault Injection Scenarios with Ease
---
### Description
FISSA is a tool designed for generating fault injection campaigns in micro-architectures, essential for assessing the security of designs against physical attacks. By deliberately introducing hardware errors into the micro-architecture of processors, FISSA allows users to test their robustness against potential hardware failures.
This open-source tool integrates with existing simulation environment like Questasim, streamlining the process of generating fault injection scenarios.

With FISSA, generating fault injection campaigns becomes more accessible, empowering users to assess the security and reliability of their designs efficiently to enable *Security By Design*.

---
### Installation
To run FISSA, ensure you have Python 3.10.12 installed on your system. If needed, you can set up a virtual environment using your preferred method.

After setting up the Python environment, install the required dependencies by running the following command:

```bash
pip3 install -r requirements.txt    
```
This command will install all the necessary dependencies specified in the requirements.txt file.
Once the dependencies are installed, you're ready to use FISSA for generating fault injection campaigns in micro-architectures.

---
### Getting started
#### Integrating your design inside FISSA

##### Generator

##### Integration with HDL Simulator

##### Analyser

#### Running FISSA
Run FISSA:
```bash
python3 __init__.py
```

You will have a contextual menu in which you will have to choose the protection you want to use. Then, the next menu will be to choose if you want to generate TCL files or analyse JSON files.

---
### Features
Users can easily define parameters such as threat models, attack windows, and registers to be attacked via configuration files, simplifying the testing process. FISSA also provides reporting functions for analysing results, and it generates TCL scripts compatible with various simulation tools.

---
### Example

---
### Roadmap

- Adding more fault models
- Add more configurability to reduce integration
- Supporting more HDL simulators (Vivado, Verilator, ...)
- Code optimisation
- Enhance integration into the design workflow by adding functionalities
- Development of a graphical user interface

---
### Contributing

---
### Contact Information
- Author: William PENSEC 

---
### Acknowledgements - Version date
- Thanks to Noura Ait Manssour for the first iteration
- 18/04/2024

---
### Citation

```

```