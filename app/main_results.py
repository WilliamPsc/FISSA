import pathlib
import yaml
from src.analyse_results import AnalyseResults


class MainResults:
    """"""

    def __init__(self, protect = "wop") -> None:
        self.__app_folder = pathlib.Path(__file__).resolve().parent
        self.__config_folder = pathlib.Path.joinpath(self.__app_folder, "config")
        self.__config_data = dict()
        self.__config_file_path = str(self.__config_folder) + "/config_" + protect + ".json"


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
        return 0

    def analyse_results(self):
        results = AnalyseResults(self.__config_data)
        results.analyse_results()