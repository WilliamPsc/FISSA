"""
# @Author : William PENSEC
# @Version : 1.0
# @Date : 19 janvier 2023
# @DateVersion : 27 février 2023
# @Description : Module principal du générateur de fichier tcl pour simuler des injections de fautes sur un processeur
"""

### Import packages ###
from datetime import datetime
from timeit import default_timer as timer
from main_results import MainResults
from main import Main


def generator(protect:str):
    start_time_main = timer()
    app_main = Main(protect=protect)
    app_main.read_config()
    app_main.launch_generator()
    end_time = timer()
    print(f'Execute time main : {round(1000*(end_time - start_time_main), 2)} ms')
    print("Time of generation :", datetime.now().strftime("%d-%m-%Y %H:%M:%S"))

def analyse_results(protect:str):
    start_time_main = timer()
    app_results = MainResults(protect)
    app_results.read_config()
    app_results.analyse_results()
    end_time = timer()
    print(f'Execute time main : {round(1000*(end_time - start_time_main), 2)} ms')
    print("Time of generation :", datetime.now().strftime("%d-%m-%Y %H:%M:%S"))


### Execute simulator ###
if __name__ == "__main__":
    print("======== List of available commands ========")
    print("\t 1- Launch Generator")
    print("\t 2- Analyse results")
    command = int(input("What do you want to execute? "))
    # command = 1

    print("======== List of protections available ========")
    print("\t 1- Without protection")
    print("\t 2- Hamming Code")
    protect_choice = int(input("Which protection do you want to use ? "))
    match protect_choice:
        case 1:
            protect = "wop"
        case 2:
            protect = "hamming"
        case 3:
            protect = "simple_parity"
        case _:
            protect = ""

    match command:
        case 1:
            generator(protect=protect)
        case 2:
            analyse_results(protect=protect)
        case _:
            print("No choice has been found. Try again.")
    