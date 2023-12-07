"""
## @Author : William PENSEC
## @Version : 0.2
## @Date : 20 janvier 2023
## @DateVersion : 05 décembre 2023
## @Description : 
"""

### Import packages ###
import os
import shutil
import yaml
import math
import pyperclip
from src.fault_injection import FaultInjection
from src.log import LogData
from src.code_execution import CodeExecute

### Class ###
class TCL:
    """TCL class to generate a tcl file to simulate a design from different parameters :
        - nb_simulations: number of simulations
        - path: path of the simulator
        - simulator: name of the simulator used (xsim, modelsim, ...)
        - commands_simulator: specific tcl commands used by the simulator
        - codes: names of the simulated programs
    """

    ## Class constructor
    # def __init__(self, nb_simulations, path, simulator, commands_simulator, codes):
    def __init__(self, config_data:dict, code:str, prot:str):
        # Initializing attributes
        self._config_data_simulator = config_data
        self._sim_path = config_data["path_tcl_generation"]
        self._name_simulator = config_data["name_simulator"]
        self._files_sim = config_data["path_files_sim"]
        self._threat_model = config_data['threat_model']
        self._code = code
        self._protection = prot
        self._res_path = config_data["path_results_sim"] + code + "/" + code + "-" + self._protection + "_" + '-'.join(self._threat_model) + "/"
        if os.path.exists(self._res_path):
            shutil.rmtree(self._res_path)
        os.makedirs(self._res_path)
        self._registers_list = list()
        self._registers_size = list()
        self._tcl_string =  list()
        self._nb_simu = 0
        self._nb_simu_total = 0
        self._code_exec = CodeExecute(config_data)
        self._log_data = LogData(config_data)
        self._inject_fault = FaultInjection(config_data)
        self._batch_number = 1
        self._batch_max_sim:int = config_data["batch_sim"]
        self._build_make_list = list()

    @property
    def sim_path(self):
        return self._sim_path
    
    @property
    def name_simulator(self):
        return self._name_simulator

    @property  
    def files_sim(self):
        return self._files_sim

    @property
    def code(self):
        return self._code
 
    @property
    def version_code(self):
        return self._protection

    @property
    def res_path(self):
        return self._res_path

    @property
    def tcl_file(self):
        return self._tcl_file

    @property
    def registers_list(self):
        '''Getter register_list : list variable'''
        return self._registers_list
    
    @registers_list.setter
    def registers_list(self, values:list):
        '''Setter register_list : list variable'''
        if(type(values) is list):
            self._registers_list = values
        else:
            self._registers_list = []

    @property
    def registers_size(self):
        '''Getter registers_size : list variable'''
        return self._registers_size
    
    @registers_size.setter
    def registers_size(self, values:list):
        '''Setter registers_size : list variable'''
        if(type(values) is list):
            self._registers_size = values
        else:
            self._registers_size = []

    @property
    def nb_simu(self):
        '''Return the number of simulations to be done'''
        return self._nb_simu_total

    @property
    def build_make_list(self):
        '''Getter build_make_list : list variable'''
        return self._build_make_list

    @build_make_list.setter
    def build_make_list(self, value:str) -> int:
        '''Setter build_make_list : list variable'''
        self._build_make_list.append(value)
        if(value in self._build_make_list):
            return 0
        else:
            return 1

    # @nb_simu.setter
    def set_nb_simu_total(self, threat_model:list, window:list):
        '''Set number of simulations to be done'''
        for threat in threat_model:
            if(threat == "set0"):
                self._nb_simu_total += (len(self._registers_list) * int((window[1] - window[0]) / 40))
            elif(threat == "set1"):
                self._nb_simu_total += (len(self._registers_list) * int((window[1] - window[0]) / 40))
            elif(threat == "bitflip"):
                self._nb_simu_total += (sum(self._registers_size) * int((window[1] - window[0]) / int(self._config_data_simulator['cpu_period'])))

    ## Fonction servant à construire la chaîne de simulation
    def build_data_string(self):
        """Function used to build the simulation TCL string"""
        path_file_sim = ''.join(self._config_data_simulator['path_simulation']).replace('__code', self._code) + "-" + self._protection + "_" + '-'.join(self._threat_model) + "/"
        reg_file_sim = path_file_sim + "faulted_regs.yaml"
        for window in self._config_data_simulator['fenetre_tir'][self._code]:
            self.set_nb_simu_total(self._config_data_simulator["threat_model"], window)
            print(f"Number of simulations to be run : {self._nb_simu_total}")
            file_number = 1
            if(self._nb_simu_total < self._batch_max_sim):
                nb_files = math.ceil(self._nb_simu_total / self._batch_max_sim)
                print("Nombre de fichiers à générer :", nb_files)
                file_str = "source\ " + str(path_file_sim) + str(self._code) + "_" + str(self._protection) + "_" + str(file_number) + ".tcl"
                self.build_make_list = file_str
                self._tcl_file = self._res_path + self._code + "_" + self._protection + "_" + str(file_number) + ".tcl"
                log_file_sim = ''.join(self._config_data_simulator['path_simulation']).replace('__code', self._code) + "-" + self._protection + "/" + self._code + "-" + self._protection + "_" + str(file_number) + ".json"
                self.build_ref_sim(reg_file_sim, log_file_sim, window, self._nb_simu_total)
                self.build_simus(window, self._nb_simu_total, self._batch_max_sim)
            else:
                nb_files = math.ceil(self._nb_simu_total / self._batch_max_sim)
                print("Nombre de fichiers à générer :", nb_files)
                for i in range(nb_files):
                    if(file_number != -1):
                        file_str = "source\ " + str(path_file_sim) + str(self._code) + "_" + str(self._protection) + "_" + str(file_number) + ".tcl"
                        self.build_make_list = file_str
                        self._tcl_file = self._res_path + self._code + "_" + self._protection + "_" + str(file_number) + ".tcl"
                        # log_file_sim = ''.join(self._config_data_simulator['path_simulation']).replace('__code', self._code) + "-" + self._protection + "/" + self._code + "-" + self._protection + "_" + str(file_number) +".json"
                        log_file_sim = ''.join(self._config_data_simulator['path_simulation']).replace('__code', self._code) + "-" + self._protection + "/" + self._code + "-" + self._protection + ".json"
                        self.build_ref_sim(reg_file_sim, log_file_sim, window, self._nb_simu_total)
                        file_number = self.build_simus(window, self._nb_simu_total, self._batch_max_sim)
        self.gen_build_make()
            
    def build_ref_sim(self, reg_file_sim, log_file_sim, fenetre, nb_simulations):
        self._tcl_string = list()
        self._tcl_string.append(self._code_exec.init_sim(reg_file_sim, log_file_sim))
        self._tcl_string.append(self._code_exec.init_tcl_variables(fenetre))
        self._tcl_string.append(self._code_exec.gen_simu_ref())
        self._tcl_string.append(self._code_exec.run_simu_ref())
        self._tcl_string.append(self._log_data.log_sim())
        self._tcl_string.append(self._code_exec.end_sim(0,nb_simulations))
        self.write_tcl_file(''.join(self._tcl_string))
     
    def build_simus(self, fenetre, nb_simulations, nb_simu_max_batch):
        self._tcl_string = list()
        for reg in self._registers_list: # attention lorsqu'un registre est un tableau de plusieurs bits
            if (reg not in self._config_data_simulator['avoid_register']):
                for threat in self._threat_model:
                    if(threat == "bitflip"):
                        for wreg in range(self._registers_size[self._registers_list.index(reg)]):
                            for start_time in range(fenetre[0], fenetre[1], 40):
                                self._tcl_string = list()
                                self._nb_simu += 1
                                self._tcl_string.append(self._code_exec.init_sim_attacked(self._nb_simu, start_time, threat, reg, self._registers_size[self._registers_list.index(reg)]))
                                self._tcl_string.append(self._inject_fault.inject_fault(wreg))
                                self._tcl_string.append(self._code_exec.run_sim_attacked())
                                self._tcl_string.append(self._log_data.log_sim())
                                self._tcl_string.append(self._code_exec.end_sim(self._nb_simu, nb_simulations))
                                try:
                                    self.write_tcl_file(''.join(self._tcl_string))
                                except TypeError as e:
                                    print("TypeError")
                                    return -1
                                if(self._nb_simu >= (nb_simu_max_batch * self._batch_number)):
                                    self._batch_number += 1
                                    return self._batch_number
                                if(self._nb_simu >= nb_simulations):
                                    return -1
                    else:
                        for start_time in range(fenetre[0], fenetre[1], 40):
                            self._tcl_string = list()
                            self._nb_simu += 1
                            self._tcl_string.append(self._code_exec.init_sim_attacked(self._nb_simu, start_time, threat, reg, self._registers_size[self._registers_list.index(reg)]))
                            self._tcl_string.append(self._inject_fault.inject_fault())
                            self._tcl_string.append(self._code_exec.run_sim_attacked())
                            self._tcl_string.append(self._log_data.log_sim())
                            self._tcl_string.append(self._code_exec.end_sim(self._nb_simu, nb_simulations))
                            try:
                                self.write_tcl_file(''.join(self._tcl_string))
                            except TypeError:
                                print(self._nb_simu, self._tcl_file, nb_simulations, nb_simu_max_batch)
                                print(self._tcl_string)
                                return -1
                            if(self._nb_simu >= (nb_simu_max_batch * self._batch_number)):
                                self._batch_number += 1
                                return self._batch_number
                            if(self._nb_simu >= nb_simulations):
                                return -1

    ## Fonction servant à écrire le fichier tcl final avec toutes les données de simulations
    def write_tcl_file(self, data):
        """Function used to write simulation string to the tcl file:
            - data: simulation string to be written
            - this function append the string to the file
        """
        try:
            with open(self._tcl_file, 'a') as tcl_f:
                tcl_f.write(data)
        except Exception as e:
            print("Une exception est survenue : {exc}".format(exc=e.args[1]))
            return 1

    ## Fonction récupérant les registres à fauter du processeur
    def read_register_list(self):
        """Function used to return the registers to be faulted:
            - return a list of all registers stored in the simuFiles/registers/registers_protection.yaml configuration file
        """
        name_regs = []
        size_regs = []
        try:
            with open(self._files_sim + "registers/registers_" + self._protection + ".yaml", "r", encoding="utf-8") as registers_file:
                try:
                    registers = yaml.safe_load(registers_file)
                except yaml.YAMLError as e:
                    print(e)
            for reg in registers:
                for data_reg in registers[reg]:
                    name_regs.append(data_reg['name'])
                    size_regs.append(data_reg['width'])
        except FileNotFoundError:
            print(f"File registers_{self._protection}.yaml not found. Please check the installation.")
            return 1
        self._registers_list = name_regs
        self._registers_size = size_regs
        return 0
    
    def write_faulted_registers_file(self):
        """Create the faulted registers file in the simulation folder."""
        try:
            with open(self._res_path + "faulted_regs.yaml", 'w') as file:
                yaml.dump(self._registers_list, file, default_flow_style=False)
        except Exception as e:
            print("An exception has occurred : {exc}".format(exc=e.args[1]))
            return 1
        return 0

    def gen_build_make(self):
        """Generate the simulation compilation string to be copied in build.make to simulate the simulations in 1 line"""
        str_to_clipboard = ""
        for elem in self._build_make_list:
            str_to_clipboard += " && tcsh -c env\ PULP_CORE=riscv\ VSIM_DIR=/home/wpensec/Documents/DRiSCY/pulpino/vsim\ TB_TEST=""\ /home/wpensec/tools_memphis/questa/questasim/linux_x86_64/vsim\ \ -c\ -64\ -do\ 'source\ tcl_files/run.tcl\;\ " + elem + "\;\ exit\;'\ > vsim.log"
        pyperclip.copy(str_to_clipboard)