"""
# @Author : William PENSEC
# @Version : 1.0
# @Date : 27 février 2023
# @DateVersion : 23 mars 2023
# @Description : Classe principale du générateur de fichier tcl pour simuler des injections de fautes sur un processeur
"""

### Import packages ###
## General modules ##
import pathlib
import yaml
## Custom modules ##
from src.tclgen import TCL

### Options ###

### MAIN CLASS ###
class Main:
    """
    Main class of the TCL file generator
    """
    
    def __init__(self, protect = "wop"):  
        """ Set all necessary file paths & define variables """
        self.__app_folder = pathlib.Path(__file__).resolve().parent
        self.__config_folder = pathlib.Path.joinpath(self.__app_folder, "config")
        self.__config_file_path = str(self.__config_folder) + "/config_" + protect + ".json"

        # Define other variables
        self.__config_data = dict()
    
    def read_config(self):
        """ Open configuration file """
        try:
            with open(self.__config_file_path, "r", encoding="utf-8") as config_file:
                self.__config_data = yaml.safe_load(config_file)
        except FileNotFoundError:
            print("File {file} not found. Please check the installation and try again.".format(file=self.__config_file_path))
            return 1
        except PermissionError:
            print("Insufficient permission to read {file} !".format(file=self.__config_file_path))
            return 2
        except Exception as e:
            print("One exception has occurred : {exc}".format(exc=e.args[1]))
            return 3
        print(">>> SUCCESS - config file read.")
        return 0

    def get_codes(self):
        return self.__config_data['codes']
    
    def get_prot(self):
        return self.__config_data["prot"]
    
    def print_config_data(self, param:str = None):
        if(param is not None):
            if(param == "--help"):
                print(list(self.__config_data.keys()))
                return 0
            else:
                try:
                    print(self.__config_data[param])
                except KeyError:
                    print("Clé non existante dans la configuration. Vérifiez l'orthographe ou la présence de la clé.")
                    return 1
        else:
            print(self.__config_data)
        return 0
    
    def copy_to_work_env():
        pass
    
    def launch_generator(self):
        protection = self.get_prot()
        codes = self.get_codes()
        # codes = ["buffer_overflow"]
        for code in codes:
            print(f"\t=============== {self.__config_data['name_results'][code]} ===============")
            print(f"\t\t >>>> {''.join(self.__config_data['threat_model'])} <<<<")
            tcl_gen = TCL(self.__config_data, code, protection)
            tcl_gen.read_register_list()
            tcl_gen.write_faulted_registers_file()
            tcl_gen.build_data_string()
            print("\n")