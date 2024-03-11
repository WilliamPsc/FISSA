"""
# @Author : William PENSEC
# @Version : 1.0
# @Date : 19 janvier 2023
# @DateVersion : 15 février 2024
# @Description : Module principal du générateur de fichier tcl pour simuler des injections de fautes sur un processeur
"""

### Import packages ###
from datetime import datetime
from timeit import default_timer as timer
from main_results import MainResults
from main import Main
from tools.performance_comparison import PerformancesComparison

def generator(protect:str):
    start_time_main = timer()
    app_main = Main(protect=protect)
    app_main.read_config()
    app_main.launch_generator()
    end_time = timer()
    print(f'\tExecute time main : {round(1000*(end_time - start_time_main), 2)} ms')
    print("\tTime of generation :", datetime.now().strftime("%d-%m-%Y %H:%M:%S"))

def analyse_results(protect:str):
    start_time_main = timer()
    app_results = MainResults(protect)
    app_results.read_config()
    app_results.analyse_results()
    end_time = timer()
    print(f'\tExecute time main : {round(1000*(end_time - start_time_main), 2)} ms')
    print("\tTime of generation :", datetime.now().strftime("%d-%m-%Y %H:%M:%S"))

def performance_comparison(protect:str, nb_repetitions):
    start_time_main = timer()
    perf = PerformancesComparison(protect)
    perf.read_register_list()
    perf.write_faulted_registers_file()
    perf.build_data_string(nb_repetitions)
    end_time = timer()
    print(f'\tExecute time main : {round(1000*(end_time - start_time_main), 2)} ms')
    print("\tTime for analyse :", datetime.now().strftime("%d-%m-%Y %H:%M:%S"))

### Execute simulator ###
if __name__ == "__main__":
    print("======== List of protections available ========")
    print("\t 1- Without protection")
    print("\t 2- Simple Parity")
    print("\t 3- Hamming Code")
    print("\t 4- BCH Code")
    input_str = input("Which protections do you want to use? Enter a list of numbers separated by spaces: ")
    protect_choice = [int(x) for x in input_str.split()]
    if all(1 <= num <= 3 for num in protect_choice):
        protection_chosen = []
        for num in protect_choice:
            if(num == 1):
                protection_chosen.append("Unprotected")
            if(num == 2):
                protection_chosen.append("Simple Parity")
            if(num == 3):
                protection_chosen.append("Hamming Code")
            if(num == 4):
                protection_chosen.append("BCH Code")
        print("You choose:", ', '.join(protection_chosen))
    else:
        protect_choice = [num for num in protect_choice if num <= 3 and num > 0]
    
    # protect_choice = [1,2]

    print("======== List of available commands ========")
    print("\t 1- Launch Generator")
    print("\t 2- Analyse results")
    print("\t 3- Performance comparison")
    command = int(input("What do you want to execute? "))
    # command = 1
    
    for protection in protect_choice:
        match protection:
            case 1:
                protect = "wop"
                protect_str = "Without protection"
            case 2:
                protect = "simple_parity"
                protect_str = "Simple Parity"
            case 3:
                protect = "hamming"
                protect_str = "Hamming Code"
            case 4:
                protect = "bch"
                protect_str = "BCH Code"
            case _:
                protect = ""
                protect_str = ""

        print(f"\n==================== >>>> {protect_str.capitalize()} <<<< ====================")

        match command:
            case 1:
                print(f"\n    ==================== >>>> Launching the generator <<<< ====================")
                generator(protect=protect)
            case 2:
                print(f"\n    ==================== >>>> Results analysis <<<< ====================")
                analyse_results(protect=protect)
            case 3:
                print(f"\n    ==================== >>>> Performance comparison <<<< ====================")
                nb_repetitions = int(input("\tHow many repetitions to you want to generate? "))
                if(nb_repetitions < 10 or nb_repetitions > 2200):
                    print("\t ⚠️  I recommend between 1,000 and 2,200 simulations, depending on the case. Try to have all simulations in 1 file. ⚠️")
                performance_comparison(protect=protect, nb_repetitions=nb_repetitions)
            case _:
                print("No choice has been found. Try again.")