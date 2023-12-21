"""
## @Author : William PENSEC
## @Version : 0.3
## @Date : 20 janvier 2023
## @DateVersion : 14 décembre 2023
## @Description : 
"""

### Import packages ###
import os
import shutil
import yaml
import math
import pyperclip
from itertools import combinations, permutations, product
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
        self.__config_data_simulator = config_data
        self.__sim_path = config_data["path_tcl_generation"]
        self.__name_simulator = config_data["name_simulator"]
        self.__files_sim = config_data["path_files_sim"]
        self.__threat_model = config_data['threat_model']
        self.__nb_faults = config_data['multi_fault_injection']
        self.__code = code
        self.__protection = prot
        self.__res_path = config_data["path_results_sim"] + code + "/" + code + "-" + self.__protection + "_" + '-'.join(self.__threat_model) + "/"
        if os.path.exists(self.__res_path):
            shutil.rmtree(self.__res_path)
        os.makedirs(self.__res_path)
        self.__registers_list = list()
        self.__registers_size = list()
        self.__tcl_string =  list()
        self.__nb_simu = 0
        self.__nb_simu_total = 0
        self.__code_exec = CodeExecute(config_data)
        self.__log_data = LogData(config_data)
        self.__inject_fault = FaultInjection(config_data)
        self.__batch_number = 1
        self.__batch_max_sim:int = config_data["batch_sim"]
        self.__build_make_list = list()

    @property
    def sim_path(self):
        return self.__sim_path
    
    @property
    def name_simulator(self):
        return self.__name_simulator

    @property  
    def files_sim(self):
        return self.__files_sim

    @property
    def code(self):
        return self.__code
 
    @property
    def version_code(self):
        return self.__protection

    @property
    def res_path(self):
        return self.__res_path

    @property
    def tcl_file(self):
        return self.__tcl_file

    @property
    def registers_list(self):
        '''Getter register_list : list variable'''
        return self.__registers_list
    
    @registers_list.setter
    def registers_list(self, values:list):
        '''Setter register_list : list variable'''
        if(type(values) is list):
            self.__registers_list = values
        else:
            self.__registers_list = []

    @property
    def registers_size(self):
        '''Getter registers_size : list variable'''
        return self.__registers_size
    
    @registers_size.setter
    def registers_size(self, values:list):
        '''Setter registers_size : list variable'''
        if(type(values) is list):
            self.__registers_size = values
        else:
            self.__registers_size = []

    @property
    def build_make_list(self):
        '''Getter build_make_list : list variable'''
        return self.__build_make_list

    @build_make_list.setter
    def build_make_list(self, value:str) -> int:
        '''Setter build_make_list : list variable'''
        self.__build_make_list.append(value)
        if(value in self.__build_make_list):
            return 0
        else:
            return 1

    @property
    def nb_simu(self):
        '''Return the number of simulations to be done'''
        return self.__nb_simu_total
    
    # @nb_simu.setter
    def set_nb_simu_total(self, threat_model: list, window: list):
        cpu_period = int(self.__config_data_simulator['cpu_period'])
        delta_window = int((window[1] - window[0]) / cpu_period)
        
        for threat in threat_model:
            match threat:
                case "set0" | "set1":
                    self.__nb_simu_total += len(self.__registers_list) * delta_window
                case "bitflip":
                    self.__nb_simu_total += sum(self.__registers_size) * delta_window
                case "multi_bitflip_spatial":
                    self.__nb_simu_total += math.comb(sum(self.__registers_size), self.__nb_faults) * delta_window
                case "multi_bitflip_temporel":
                    self.__nb_simu_total += int(math.pow(sum(self.__registers_size), self.__nb_faults) * math.comb(delta_window, self.__nb_faults))
                case _:
                    self.__nb_simu_total = 0

    ## Fonction servant à construire la chaîne de simulation
    def build_data_string(self):
        """Function used to build the simulation TCL string"""
        self.__path_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "-" + self.__protection + "_" + '-'.join(self.__threat_model) + "/"
        self.__reg_file_sim = self.__path_file_sim + "faulted_regs.yaml"
        self.__file_number = 1
        for window in self.__config_data_simulator['fenetre_tir'][self.__code]:
            self.set_nb_simu_total(self.__config_data_simulator["threat_model"], window)
            print(f"Number of simulations to execute: {self.__nb_simu_total}")

            self.__nb_files = math.ceil(self.__nb_simu_total / self.__batch_max_sim)
            print("Number of files to generate:", self.__nb_files)

            file_str = "source\ " + str(self.__path_file_sim) + str(self.__code) + "_" + str(self.__protection) + "_" + str(self.__file_number) + ".tcl"
            self.build_make_list = file_str
            log_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "-" + self.__protection + "_" + '-'.join(self.__threat_model) + "/" + self.__code + "-" + self.__protection + "_" + str(self.__file_number) + ".json"

            self.__tcl_file = self.__res_path + self.__code + "_" + self.__protection + "_" + str(self.__file_number) + ".tcl"

            self.build_ref_sim(log_file_sim, window, self.__nb_simu_total, 1)
            self.build_faulted_simu(window, self.__nb_simu_total)
        self.gen_build_make()

    def gen_new_file(self, window):
        self.__file_number += 1
        file_str = "source\ " + str(self.__path_file_sim) + str(self.__code) + "_" + str(self.__protection) + "_" + str(self.__file_number) + ".tcl"
        self.build_make_list = file_str
        self.__tcl_file = self.__res_path + self.__code + "_" + self.__protection + "_" + str(self.__file_number) + ".tcl"
        # log_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "-" + self.__protection + "_" + '-'.join(self.__threat_model) + "/" + self.__code + "-" + self.__protection + "_" + str(self.__file_number) + ".json"
        log_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "-" + self.__protection + "_" + '-'.join(self.__threat_model) + "/" + self.__code + "-" + self.__protection + "_1.json"
        self.build_ref_sim(log_file_sim, window, self.__nb_simu_total, self.__file_number)

    def build_faulted_simu(self, window, nb_simulations):
        for threat in self.__threat_model:
            if(threat == "multi_bitflip_spatial"):
                self.build_multi_bitflip_spatial(window, nb_simulations)
            elif(threat == "multi_bitflip_temporel"):
                self.build_multi_bitflip_temporel(window, nb_simulations)
            elif(threat == "bitflip"):
                for reg in self.__registers_list:
                    if(reg not in self.__config_data_simulator['avoid_register']):
                        for wreg in range(self.__registers_size[self.__registers_list.index(reg)]):
                            for start_time in range(window[0], window[1], 40):
                                self.build_bitflip_simu(start_time, reg, wreg, nb_simulations)
                                if(self.__nb_simu >= (self.__batch_max_sim * self.__batch_number)):
                                    self.__batch_number += 1
            else:
                for reg in self.__registers_list:
                    if(reg not in self.__config_data_simulator['avoid_register']):
                        for start_time in range(window[0], window[1], 40):
                            match threat:
                                case "set0":
                                    self.build_bit_reset_simu(start_time, reg, nb_simulations)
                                case "set1":
                                    self.build_bit_set_simu(start_time, reg, nb_simulations)
                                case _:
                                    print("Unknown threat model. You forgot to define it.")
                                    exit(1)
                            if(self.__nb_simu >= (self.__batch_max_sim * self.__batch_number)):
                                self.__batch_number += 1

    def build_ref_sim(self, log_file_sim, window, nb_simulations, nb_file = 1):
        self.__tcl_string = list()
        self.__tcl_string.append(self.__code_exec.init_sim(self.__reg_file_sim , log_file_sim, nb_file))
        self.__tcl_string.append(self.__code_exec.init_tcl_variables(window))
        self.__tcl_string.append(self.__code_exec.gen_simu_ref())
        self.__tcl_string.append(self.__code_exec.run_simu_ref())
        self.__tcl_string.append(self.__log_data.log_sim(nb_file, threat="simu0"))
        self.__tcl_string.append(self.__code_exec.end_sim(0,nb_simulations))
        try:
            self.write_tcl_file(''.join(self.__tcl_string))
        except TypeError:
            print("TypeError happened")
            exit(1)

    def build_bit_reset_simu(self, start_time, reg, nb_simulations):
        self.__tcl_string = list()
        self.__nb_simu += 1
        self.__tcl_string.append(self.__code_exec.init_sim_attacked(self.__nb_simu, start_time, "set0", reg, self.__registers_size[self.__registers_list.index(reg)]))
        self.__tcl_string.append(self.__inject_fault.inject_fault("set0"))
        self.__tcl_string.append(self.__code_exec.run_sim_attacked())
        self.__tcl_string.append(self.__log_data.log_sim(threat="set0"))
        self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
        try:
            self.write_tcl_file(''.join(self.__tcl_string))
        except TypeError:
            print("TypeError happened")
            exit(1)

    def build_bit_set_simu(self, start_time, reg, nb_simulations):
        self.__tcl_string = list()
        self.__nb_simu += 1
        self.__tcl_string.append(self.__code_exec.init_sim_attacked(self.__nb_simu, start_time, "set1", reg, self.__registers_size[self.__registers_list.index(reg)]))
        self.__tcl_string.append(self.__inject_fault.inject_fault("set1"))
        self.__tcl_string.append(self.__code_exec.run_sim_attacked())
        self.__tcl_string.append(self.__log_data.log_sim(threat="set1"))
        self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
        try:
            self.write_tcl_file(''.join(self.__tcl_string))
        except TypeError:
            print("TypeError happened")
            exit(1)

    def build_bitflip_simu(self, start_time, reg, wreg, nb_simulations):
        self.__nb_simu += 1
        self.__tcl_string.append(self.__code_exec.init_sim_attacked(self.__nb_simu, start_time, "bitflip", reg, self.__registers_size[self.__registers_list.index(reg)]))
        self.__tcl_string.append(self.__inject_fault.inject_fault("bitflip", wreg))
        self.__tcl_string.append(self.__code_exec.run_sim_attacked())
        self.__tcl_string.append(self.__log_data.log_sim(threat="bitflip"))
        self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
        try:
            self.write_tcl_file(''.join(self.__tcl_string))
        except TypeError:
            print("TypeError happened")
            exit(1)

    def build_multi_bitflip_spatial(self, window, nb_simulations):
        print("Number of registers to be targeted: ", len(self.__registers_list))
        full_list_registre_with_size = list()
        for reg in self.__registers_list:
            if(reg not in self.__config_data_simulator['avoid_register']):
                for bit in range(self.__registers_size[self.__registers_list.index(reg)]):
                    concat_reg = reg + "[" + str(bit) + "]"
                    full_list_registre_with_size.append(concat_reg)
        combinations_list = list(combinations(full_list_registre_with_size, 2))
        print("Number of possible combinations: ", len(combinations_list))

        for reg1, reg2 in combinations_list:
            for start_time in range(window[0], window[1], 40):
                self.__tcl_string = list()
                self.__nb_simu += 1
                bit_flip_0 = -1
                bit_flip_1 = -1
                size_reg_0 = 0
                size_reg_1 = 0
                if("/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg" not in reg1):
                    if("/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg" not in reg2):
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, start_time, "multi_bitflip_spatial", reg1.split("[")[0], self.__registers_size[self.__registers_list.index(reg1.split("[")[0])], reg2.split("[")[0], self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]))
                        bit_flip_0 = reg1.split("[")[1][:-1]
                        bit_flip_1 = reg2.split("[")[1][:-1]
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1.split("[")[0])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]
                    else:
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, start_time, "multi_bitflip_spatial", reg1.split("[")[0], self.__registers_size[self.__registers_list.index(reg1.split("[")[0])], reg2[:-3], self.__registers_size[self.__registers_list.index(reg2[:-3])]))
                        bit_flip_0 = reg1.split("[")[1][:-1]
                        bit_flip_1 = 0
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1.split("[")[0])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2[:-3])]
                else:
                    if("/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg" not in reg2):
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, start_time, "multi_bitflip_spatial", reg1[:-3], self.__registers_size[self.__registers_list.index(reg1[:-3])], reg2.split("[")[0], self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]))
                        bit_flip_0 = 0
                        bit_flip_1 = reg2.split("[")[1][:-1]
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1[:-3])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]
                    else:
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, start_time, "multi_bitflip_spatial", reg1[:-3], self.__registers_size[self.__registers_list.index(reg1[:-3])], reg2[:-3], self.__registers_size[self.__registers_list.index(reg2[:-3])]))
                        bit_flip_0 = 0
                        bit_flip_1 = 0
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1[:-3])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2[:-3])]
                self.__tcl_string.append(self.__inject_fault.inject_fault("multi_bitflip_spatial", bit_flip_0, bit_flip_1, size_reg_0, size_reg_1))
                self.__tcl_string.append(self.__code_exec.run_sim_attacked_hamming())
                self.__tcl_string.append(self.__log_data.log_sim(threat="multi_bitflip_spatial"))
                self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
                try:
                    self.write_tcl_file(''.join(self.__tcl_string))
                except TypeError:
                    print("TypeError happened -- multi_bitflip_spatial")
                    exit(1)
                if(self.__nb_simu >= (self.__batch_max_sim * self.__batch_number)):
                    self.__batch_number += 1
                    self.gen_new_file(window)
            
    def build_multi_bitflip_temporel(self, window, nb_simulations):
        print("Number of registers to be targeted : ", len(self.__registers_list))
        full_list_registre_with_size = list()
        for reg in self.__registers_list:
            if(reg not in self.__config_data_simulator['avoid_register']):
                for bit in range(self.__registers_size[self.__registers_list.index(reg)]):
                    concat_reg = reg + "[" + str(bit) + "]"
                    full_list_registre_with_size.append(concat_reg)
        permutations_list = list(product(full_list_registre_with_size, repeat=int(self.__config_data_simulator['multi_fault_injection'])))
        print("Number of possible permutations: ", len(permutations_list))

        combinations_list_window = list(combinations(range(window[0], window[1], int(self.__config_data_simulator['cpu_period'])), int(self.__config_data_simulator['multi_fault_injection'])))
        print("Number of possible combinations in attack window: ", len(combinations_list_window))
        
        for reg1, reg2 in permutations_list:
            for t_reg1, t_reg2 in combinations_list_window:
                self.__tcl_string = list()
                self.__nb_simu += 1
                bit_flip_0 = -1
                bit_flip_1 = -1
                size_reg_0 = 0
                size_reg_1 = 0
                if("/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg" not in reg1):
                    if("/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg" not in reg2):
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip_temporel(self.__nb_simu, t_reg1, "multi_bitflip_temporel", reg1.split("[")[0], self.__registers_size[self.__registers_list.index(reg1.split("[")[0])], reg2.split("[")[0], self.__registers_size[self.__registers_list.index(reg2.split("[")[0])], t_reg1, t_reg2))
                        bit_flip_0 = reg1.split("[")[1][:-1]
                        bit_flip_1 = reg2.split("[")[1][:-1]
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1.split("[")[0])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]
                    else:
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, t_reg1, "multi_bitflip_temporel", reg1.split("[")[0], self.__registers_size[self.__registers_list.index(reg1.split("[")[0])], reg2[:-3], self.__registers_size[self.__registers_list.index(reg2[:-3])], t_reg1, t_reg2))
                        bit_flip_0 = reg1.split("[")[1][:-1]
                        bit_flip_1 = 0
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1.split("[")[0])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2[:-3])]
                else:
                    if("/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg" not in reg2):
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, t_reg1, "multi_bitflip_temporel", reg1[:-3], self.__registers_size[self.__registers_list.index(reg1[:-3])], reg2.split("[")[0], self.__registers_size[self.__registers_list.index(reg2.split("[")[0])], t_reg1, t_reg2))
                        bit_flip_0 = 0
                        bit_flip_1 = reg2.split("[")[1][:-1]
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1[:-3])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]
                    else:
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, t_reg1, "multi_bitflip_temporel", reg1[:-3], self.__registers_size[self.__registers_list.index(reg1[:-3])], reg2[:-3], self.__registers_size[self.__registers_list.index(reg2[:-3])], t_reg1, t_reg2))
                        bit_flip_0 = 0
                        bit_flip_1 = 0
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1[:-3])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2[:-3])]
                # self.__tcl_string.append(self.__code_exec.inject_fault_run_sim_attacked_multi_bitflip_temporel(bit_flip_0, bit_flip_1, size_reg_0, size_reg_1, t_reg1, t_reg2))   
                # self.__tcl_string.append(self.__log_data.log_sim(threat="multi_bitflip_temporel"))
                self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
                try:
                    self.write_tcl_file(''.join(self.__tcl_string))
                except TypeError:
                    print("TypeError happened -- multi_bitflip_temporel")
                    exit(1)
                if(self.__nb_simu >= (self.__batch_max_sim * self.__batch_number)):
                    self.__batch_number += 1
                    self.gen_new_file(window)
                exit(1)

    ## Fonction servant à écrire le fichier tcl final avec toutes les données de simulations
    def write_tcl_file(self, data):
        """Function used to write simulation string to the tcl file:
            - data: simulation string to be written
            - this function append the string to the file
        """
        try:
            with open(self.__tcl_file, 'a') as tcl_f:
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
            with open(self.__files_sim + "registers/registers_" + self.__protection + ".yaml", "r", encoding="utf-8") as registers_file:
                try:
                    registers = yaml.safe_load(registers_file)
                except yaml.YAMLError as e:
                    print(e)
            for reg in registers:
                for data_reg in registers[reg]:
                    name_regs.append(data_reg['name'])
                    size_regs.append(data_reg['width'])
        except FileNotFoundError:
            print(f"File registers_{self.__protection}.yaml not found. Please check the installation.")
            return 1
        self.__registers_list = name_regs
        self.__registers_size = size_regs
        return 0
    
    def write_faulted_registers_file(self):
        """Create the faulted registers file in the simulation folder."""
        try:
            with open(self.__res_path + "faulted_regs.yaml", 'w') as file:
                yaml.dump(self.__registers_list, file, default_flow_style=False)
        except Exception as e:
            print("An exception has occurred : {exc}".format(exc=e.args[1]))
            return 1
        return 0

    def gen_build_make(self):
        """Generate the simulation compilation string to be copied in build.make to simulate the simulations in 1 line"""
        str_to_clipboard = ""
        if (len(self.__build_make_list) != 0):
            str_to_clipboard = "cd /home/wpensec/Documents/DRiSCY/pulpino/sw/build/apps/" + self.__code
            for elem in self.__build_make_list:
                str_to_clipboard += " && tcsh -c env\ PULP_CORE=riscv\ VSIM_DIR=/home/wpensec/Documents/DRiSCY/pulpino/vsim\ TB_TEST=\"\"\ /home/wpensec/tools_memphis/questa/questasim/linux_x86_64/vsim\ \ -c\ -64\ -do\ 'source\ tcl_files/run.tcl\;\ " + elem + "\;\ exit\;'\ > vsim.log"
            # pyperclip.copy(str_to_clipboard)
            # print(str_to_clipboard)