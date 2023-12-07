"""
# @Author : William PENSEC
# @Version : 1.0
# @Date : 19 janvier 2023
# @DateVersion : 27 février 2023
# @Description : Module principal du générateur de fichier tcl pour simuler des injections de fautes sur un processeur
"""

### Import packages ###
from timeit import default_timer as timer
from main import Main

### Execute simulator ###
if __name__ == "__main__":
    start_time_main = timer()
    protect = "wop"
    app_main = Main(protect=protect)
    app_main.read_config()
    app_main.launch_generator()
    end_time = timer()
    print(f'Execute time main : {round(1000*(end_time - start_time_main), 2)} ms')