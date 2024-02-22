"""
## @Author : William PENSEC
## @Version : 0.0
## @Date : 14 février 2023
## @Description :
"""

### Import packages ###
import os
import pathlib
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime

import yaml

### Class ###
class AnalysePerformances:
    """Analyses the results of simulations and manages the analysis in table or graph"""
    def __init__(self, protect = "wop"):
        self.__protection = protect
        self.__table_data = pd.DataFrame()
        self.read_config()

    def calculate_time_difference(self, start, end):
        # Convert the date strings to datetime objects
        date_format = "%Y/%m/%d:%H:%M:%S"
        date1 = datetime.strptime(start, date_format)
        date2 = datetime.strptime(end, date_format)

        # Calculate the difference between the two dates in seconds
        time_difference_seconds = int((date2 - date1).total_seconds())

        # Print the difference in seconds
        print(f"\t\t\t>>>> The simulation time was: {time_difference_seconds} seconds")

    def analyse_results(self):
        """"""
        applications = ["buffer_overflow"]
        for appli in applications:
            self.__table_data = pd.DataFrame()
            print("=================== Buffer Overflow ===================")
            print("\t======= >>> Performance analysis <<< =======")
            # Ouverture de chaque fichier résultat
            print("\t\t>>> Opening result file")
            path_to_filename = os.path.join(self.__config_data["path_results_sim"], appli, f"{appli}_{self.__config_data['prot']}_performance_comparison/")
            # Check if the directory exists
            if os.path.exists(path_to_filename):
                json_files = [pos_json for pos_json in os.listdir(path_to_filename) if pos_json.endswith('.json')] # Enregistrement sous forme de DataFrame panda
                if(len(json_files) != 0):
                    print("\t\t>>> READING FILE ...")
                    for file in json_files:
                        start_value = 0
                        end_value = 0
                        start = None
                        end = None
                        try:
                            value_basique = pd.read_json(os.path.join(path_to_filename, file)).transpose()
                            if (file.endswith('_2.json')):
                                print(f"\t\t>>> Time taken for {len(value_basique) - 2} faulted simulations ...")
                            if (file.endswith('_1.json')):
                                print(f"\t\t>>> Time taken for {len(value_basique) - 2} not faulted simulations ...")
                        except ValueError as e:
                            print(f"Error reading JSON file {os.path.join(path_to_filename, file)}: {e}")
                            continue
                        # Extract values associated with 'start' and 'end' from index
                        if 'start' in value_basique.index:
                            start = value_basique.loc['start'].iloc[0]  # Assuming 'start' is in the index
                        if start_value == 0 and start != None:
                            start_value = start

                        if 'end' in value_basique.index:
                            end = value_basique.loc['end'].iloc[0]  # Assuming 'end' is in the index
                        if end_value == 0 and end != None:
                            end_value = end
                        
                        # self.__table_data = self.__table_data.drop(index=['start', 'simulation_0', 'end'])
                        if(start_value != 0 and end_value != 0):
                            self.calculate_time_difference(start_value, end_value)
                    # =================================================
                else:
                    print(f"The directory \"{path_to_filename}\" is empty.")
            else:
                print(f"The directory \"{path_to_filename}\" does not exist.")

    def read_config(self):
        """ Open configuration file """
        self.__app_folder = pathlib.Path(__file__).resolve().parent.parent
        self.__config_folder = pathlib.Path.joinpath(self.__app_folder, "config")
        self.__config_file_path = str(self.__config_folder) + "/config_" + self.__protection + ".json"
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
        return 0

if __name__ == "__main__":
    analyse = AnalysePerformances()
    analyse.analyse_results()
