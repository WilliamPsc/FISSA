"""
## @Author : William PENSEC
## @Version : 0.3
## @Date : 20 janvier 2023
## @DateVersion : 06 février 2024
## @Description : 
"""

### Import packages ###
import os
import yaml
import math
from itertools import combinations, product
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
        self.__gen_path = config_data["path_generated_sim"] + code + "/" + code + "_" + self.__protection + "_" + '-'.join(self.__threat_model) + "_" + str(self.__nb_faults) + "/"
        if os.path.exists(self.__gen_path):
            # Iterate over each file in the folder
            for filename in os.listdir(self.__gen_path):
                file_path = os.path.join(self.__gen_path, filename)
                # Check if the file is a regular file and not a .json file
                if os.path.isfile(file_path) and not filename.endswith('.json'):
                    # Delete the file
                    os.remove(file_path)
        else:
            os.makedirs(self.__gen_path)
            os.makedirs(self.__gen_path + "results/")
        
        self.__res_path = config_data["path_results_sim"] + code + "/" + code + "_" + self.__protection + "_" + '-'.join(self.__threat_model) + "_" + str(self.__nb_faults) + "/"
        if os.path.exists(self.__res_path):
            # Iterate over each file in the folder
            for filename in os.listdir(self.__res_path):
                file_path = os.path.join(self.__res_path, filename)
                # Check if the file is a regular file and not a .json file
                if os.path.isfile(file_path) and not filename.endswith('.json'):
                    # Delete the file
                    os.remove(file_path)
        else:
            os.makedirs(self.__res_path)
        self.__registers_list = list()
        self.__registers_size = list()
        self.__tcl_string =  list()
        self.__nb_simu = 0
        self.__nb_simu_total = 0
        self.__code_exec = CodeExecute(config_data, self.__code)
        self.__log_data = LogData(config_data)
        self.__inject_fault = FaultInjection(config_data)
        self.__batch_number = 1
        self.__res_file = 1
        self.__batch_max_sim:int = config_data["batch_sim"][self.__code]
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
    def gen_path(self):
        return self.__gen_path

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
    def nb_simu(self) -> int:
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
                case "single_bitflip_spatial":
                    self.__nb_simu_total += math.comb(sum(self.__registers_size), self.__nb_faults) * delta_window
                case "single_bitflip_temporel":
                    self.__nb_simu_total += int(math.pow(sum(self.__registers_size), self.__nb_faults) * math.comb(delta_window, self.__nb_faults))
                case "multi_bitflip_reg":
                    for index, register in enumerate(self.__registers_list):
                        size = self.__registers_size[index]
                        if (size >= 1 and size < 16):
                            self.__nb_simu_total += int(math.pow(2,size)) * delta_window
                case "multi_bitflip_reg_multi":
                    valid_registers = [(reg1, reg2)
                                       for (reg1, size1), (reg2, size2) in combinations(zip(self.__registers_list, self.__registers_size), 2)
                                       if 1 <= size1 < 10 and 1 <= size2 < 10]
                    for index, (register_1, register_2) in enumerate(valid_registers):
                        index_1 = self.__registers_list.index(register_1)
                        index_2 = self.__registers_list.index(register_2)
                        size_1 = self.__registers_size[index_1]
                        size_2 = self.__registers_size[index_2]

                        self.__nb_simu_total += int(math.pow(2,size_1)) * int(math.pow(2,size_2)) * delta_window
                case _:
                    self.__nb_simu_total = 0

    ## Fonction servant à construire la chaîne de simulation
    def build_data_string(self):
        """Function used to build the simulation TCL string"""
        self.__path_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "_" + self.__protection + "_" + '-'.join(self.__threat_model) + "_" + str(self.__nb_faults) + "/"
        self.__reg_file_sim = self.__path_file_sim + "faulted_regs.yaml"
        self.__file_number = 1
        for window in self.__config_data_simulator['fenetre_tir'][self.__code]:
            self.set_nb_simu_total(self.__config_data_simulator["threat_model"], window)
            print(f"\t\t >>>> Number of simulations to execute: {'{:,}'.format(self.__nb_simu_total).replace(',', ' ')}")

            self.__nb_files = math.ceil(self.__nb_simu_total / self.__batch_max_sim)
            print("\t\t >>>> Number of files to generate:", '{:,}'.format(self.__nb_files).replace(',', ' '))
            print(f"\t\t >>>> Number of batch: {self.__config_data_simulator['multi_res_files'][self.__code]}")

            file_str = "source\ " + str(self.__path_file_sim) + str(self.__code) + "_" + str(self.__protection) + "_" + str(self.__file_number) + ".tcl"
            self.build_make_list = file_str
            log_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "_" + self.__protection + "_" + '-'.join(self.__threat_model) + "_" + str(self.__nb_faults) + "/results/" + self.__code + "_" + self.__protection + "_" + str(self.__file_number) + ".json"

            self.__tcl_file = self.__gen_path + self.__code + "_" + self.__protection + "_" + str(self.__file_number) + ".tcl"

            self.build_ref_sim(log_file_sim, window, self.__nb_simu_total, 1)
            self.build_faulted_simu(window, self.__nb_simu_total)
        self.gen_build_make()

    def gen_new_file(self, window):
        self.__file_number += 1
        file_str = "source\ " + str(self.__path_file_sim) + str(self.__code) + "_" + str(self.__protection) + "_" + str(self.__file_number) + ".tcl"
        self.build_make_list = file_str
        self.__tcl_file = self.__gen_path + self.__code + "_" + self.__protection + "_" + str(self.__file_number) + ".tcl"

        if(self.__config_data_simulator['multi_res_files'][self.__code] < 1):
            self.__config_data_simulator['multi_res_files'][self.__code] = 1

        if(self.__config_data_simulator['multi_res_files'][self.__code] == 1):
            log_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "_" + self.__protection + "_" + '-'.join(self.__threat_model) + "_" + str(self.__nb_faults) + "/results/" + self.__code + "_" + self.__protection + "_1.json"
        else:
            log_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "_" + self.__protection + "_" + '-'.join(self.__threat_model) + "_" + str(self.__nb_faults) + "/results/" + self.__code + "_" + self.__protection + "_" + str(self.__file_number) + ".json"
        
        self.build_ref_sim(log_file_sim, window, self.__nb_simu_total, self.__file_number)

    def build_faulted_simu(self, window, nb_simulations):
        for threat in self.__threat_model:
            if(threat == "single_bitflip_spatial"):
                print("\t\t >>>> Single bit-flip spatial")
                self.build_single_bitflip_spatial(window, nb_simulations)
            elif(threat == "single_bitflip_temporel"):
                print("\t\t >>>> Single bit-flip temporel")
                self.build_single_bitflip_temporel(window, nb_simulations)
            elif(threat == "multi_bitflip_reg"):
                print("\t\t >>>> Multiples bit-flip inside a register")
                self.build_multi_bitflip_reg(window, nb_simulations)
            elif(threat == "multi_bitflip_reg_multi"):
                print("\t\t >>>> Multiples bit-flip inside 2 registers")
                self.build_multi_bitflip_reg_multi(window, nb_simulations)
            elif(threat == "bitflip"):
                print("\t\t >>>> Single bit-flip")
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
        self.__tcl_string = list()
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

    def build_single_bitflip_spatial(self, window, nb_simulations):
        print("\t\t\t >>>> Number of registers to be targeted: ", len(self.__registers_list))
        print("\t\t\t >>>> Number of bits to be targeted: ", sum(self.__registers_size))
        full_list_registre_with_size = list()
        for reg in self.__registers_list:
            if(reg not in self.__config_data_simulator['avoid_register']):
                for bit in range(self.__registers_size[self.__registers_list.index(reg)]):
                    concat_reg = reg + "[" + str(bit) + "]"
                    full_list_registre_with_size.append(concat_reg)
        combinations_list = list(combinations(full_list_registre_with_size, self.__nb_faults))
        print("\t\t\t >>>> Number of possible combinations: ", len(combinations_list))

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
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, start_time, "single_bitflip_spatial", reg1.split("[")[0], self.__registers_size[self.__registers_list.index(reg1.split("[")[0])], reg2.split("[")[0], self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]))
                        bit_flip_0 = reg1.split("[")[1][:-1]
                        bit_flip_1 = reg2.split("[")[1][:-1]
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1.split("[")[0])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]
                    else:
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, start_time, "single_bitflip_spatial", reg1.split("[")[0], self.__registers_size[self.__registers_list.index(reg1.split("[")[0])], reg2[:-3], self.__registers_size[self.__registers_list.index(reg2[:-3])]))
                        bit_flip_0 = reg1.split("[")[1][:-1]
                        bit_flip_1 = 0
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1.split("[")[0])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2[:-3])]
                else:
                    if("/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg" not in reg2):
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, start_time, "single_bitflip_spatial", reg1[:-3], self.__registers_size[self.__registers_list.index(reg1[:-3])], reg2.split("[")[0], self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]))
                        bit_flip_0 = 0
                        bit_flip_1 = reg2.split("[")[1][:-1]
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1[:-3])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]
                    else:
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip(self.__nb_simu, start_time, "single_bitflip_spatial", reg1[:-3], self.__registers_size[self.__registers_list.index(reg1[:-3])], reg2[:-3], self.__registers_size[self.__registers_list.index(reg2[:-3])]))
                        bit_flip_0 = 0
                        bit_flip_1 = 0
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1[:-3])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2[:-3])]
                self.__tcl_string.append(self.__inject_fault.inject_fault("single_bitflip_spatial", bit_flip_0, bit_flip_1, size_reg_0, size_reg_1))
                if(self.__protection == "wop"):
                    self.__tcl_string.append(self.__code_exec.run_sim_attacked())
                elif(self.__protection == "hamming"):
                    self.__tcl_string.append(self.__code_exec.run_sim_attacked_hamming())
                elif(self.__protection == "secded"):
                    self.__tcl_string.append(self.__code_exec.run_sim_attacked_secded())
                self.__tcl_string.append(self.__log_data.log_sim(threat="single_bitflip_spatial"))
                self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
                try:
                    self.write_tcl_file(''.join(self.__tcl_string))
                except TypeError:
                    print("TypeError happened -- single_bitflip_spatial")
                    exit(1)
                if(self.__nb_simu >= (self.__batch_max_sim * self.__batch_number)):
                    self.__batch_number += 1
                    self.gen_new_file(window)
            
    def build_single_bitflip_temporel(self, window, nb_simulations):
        print("\t\t\t >>>> Number of registers to be targeted / Number of registers :", len(self.__registers_list), "/", len(self.__registers_list))
        full_list_registre_with_size = list()
        for reg in self.__registers_list:
            if(reg not in self.__config_data_simulator['avoid_register']):
                for bit in range(self.__registers_size[self.__registers_list.index(reg)]):
                    concat_reg = reg + "[" + str(bit) + "]"
                    full_list_registre_with_size.append(concat_reg)
        permutations_list = list(product(full_list_registre_with_size, repeat=int(self.__config_data_simulator['multi_fault_injection'])))
        print("\t\t\t >>>> Number of possible permutations: ", len(permutations_list))

        combinations_list_window = list(combinations(range(window[0], window[1], int(self.__config_data_simulator['cpu_period'])), int(self.__config_data_simulator['multi_fault_injection'])))
        print("\t\t\t >>>> Number of possible combinations in attack window: ", len(combinations_list_window))

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
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_single_bitflip_temporel(self.__nb_simu, t_reg1, "single_bitflip_temporel", reg1.split("[")[0], self.__registers_size[self.__registers_list.index(reg1.split("[")[0])], reg2.split("[")[0], self.__registers_size[self.__registers_list.index(reg2.split("[")[0])], t_reg1, t_reg2))
                        bit_flip_0 = reg1.split("[")[1][:-1]
                        bit_flip_1 = reg2.split("[")[1][:-1]
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1.split("[")[0])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]
                    else:
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_single_bitflip_temporel(self.__nb_simu, t_reg1, "single_bitflip_temporel", reg1.split("[")[0], self.__registers_size[self.__registers_list.index(reg1.split("[")[0])], reg2[:-3], self.__registers_size[self.__registers_list.index(reg2[:-3])], t_reg1, t_reg2))
                        bit_flip_0 = reg1.split("[")[1][:-1]
                        bit_flip_1 = 0
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1.split("[")[0])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2[:-3])]
                else:
                    if("/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg" not in reg2):
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_single_bitflip_temporel(self.__nb_simu, t_reg1, "single_bitflip_temporel", reg1[:-3], self.__registers_size[self.__registers_list.index(reg1[:-3])], reg2.split("[")[0], self.__registers_size[self.__registers_list.index(reg2.split("[")[0])], t_reg1, t_reg2))
                        bit_flip_0 = 0
                        bit_flip_1 = reg2.split("[")[1][:-1]
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1[:-3])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2.split("[")[0])]
                    else:
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_single_bitflip_temporel(self.__nb_simu, t_reg1, "single_bitflip_temporel", reg1[:-3], self.__registers_size[self.__registers_list.index(reg1[:-3])], reg2[:-3], self.__registers_size[self.__registers_list.index(reg2[:-3])], t_reg1, t_reg2))
                        bit_flip_0 = 0
                        bit_flip_1 = 0
                        size_reg_0 = self.__registers_size[self.__registers_list.index(reg1[:-3])]
                        size_reg_1 = self.__registers_size[self.__registers_list.index(reg2[:-3])]
                inject_fault = self.__inject_fault.inject_fault("single_bitflip_temporel", bit_flip_0, bit_flip_1, size_reg_0, size_reg_1)
                self.__tcl_string.append(self.__code_exec.run_sim_attacked_single_bitflip_temporel(fault_injection=inject_fault))   
                self.__tcl_string.append(self.__log_data.log_sim(threat="single_bitflip_temporel"))
                self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
                try:
                    self.write_tcl_file(''.join(self.__tcl_string))
                except TypeError:
                    print("TypeError happened -- single_bitflip_temporel")
                    exit(1)
                if(self.__nb_simu >= (self.__batch_max_sim * self.__batch_number)):
                    self.__batch_number += 1
                    self.gen_new_file(window)

    def build_multi_bitflip_reg(self, window, nb_simulations):
        """"""
        relevant_reg = list()
        relevant_reg_size = list()
        for index, register in enumerate(self.__registers_list):
            size = self.__registers_size[index]
            if (size >= 1 and size < 16):
                relevant_reg.append(register)
                relevant_reg_size.append(size)
        print("\t\t\t >>>> Number of registers to be targeted / Number of registers :", len(relevant_reg), "/", len(self.__registers_list))

        for index, register in enumerate(relevant_reg):
            size_reg = relevant_reg_size[index]
            for size in range(int(math.pow(2,size_reg))):
                for start_time in range(window[0], window[1], 40):
                    self.__tcl_string = list()
                    self.__nb_simu += 1
                    self.__tcl_string.append(self.__code_exec.init_sim_attacked(self.__nb_simu, start_time, "multi_bitflip_reg", register, size_reg))
                    self.__tcl_string.append(self.__inject_fault.inject_fault("multi_bitflip_reg", bin(size)[2:]))
                    if(self.__protection == "wop"):
                        self.__tcl_string.append(self.__code_exec.run_sim_attacked())
                    if(self.__protection == "simple_parity"):
                        self.__tcl_string.append(self.__code_exec.run_sim_attacked_simple())
                    elif(self.__protection == "hamming"):
                        self.__tcl_string.append(self.__code_exec.run_sim_attacked_hamming())
                    self.__tcl_string.append(self.__log_data.log_sim(threat="multi_bitflip_reg"))
                    self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
                    try:
                        self.write_tcl_file(''.join(self.__tcl_string))
                    except TypeError as e:
                        print("TypeError happened -- multi_bitflip_reg\n", e)
                        exit(1)
                    if(self.__nb_simu >= (self.__batch_max_sim * self.__batch_number)):
                        self.__batch_number += 1
                        self.gen_new_file(window)

    def build_multi_bitflip_reg_multi(self, window, nb_simulations):
        """"""
        valid_registers = [(reg1, size1, reg2, size2)
                           for (reg1, size1), (reg2, size2) in combinations(zip(self.__registers_list, self.__registers_size), 2)
                           if 1 <= size1 < 10 and 1 <= size2 < 10]

        nb_valid_reg = sum(1 for size in self.__registers_size if 1 <= size < 10)

        print("\t\t\t >>>> Number of registers to be targeted / Number of registers :", nb_valid_reg, "/", len(self.__registers_list))

        for index, (register_1, size_1, register_2, size_2) in enumerate(valid_registers):
            for size1 in range(int(math.pow(2,size_1))):
                for size2 in range(int(math.pow(2,size_2))):
                    for start_time in range(window[0], window[1], 40):
                        self.__tcl_string = list()
                        self.__nb_simu += 1
                        self.__tcl_string.append(self.__code_exec.init_sim_attacked_multi_bitflip_reg_multi(self.__nb_simu, start_time, "multi_bitflip_reg_multi", register_1, size_1, register_2, size_2))
                        self.__tcl_string.append(self.__inject_fault.inject_fault("multi_bitflip_reg_multi", bit_flipped_0=bin(size1)[2:], bit_flipped_1=bin(size2)[2:]))
                        if(self.__protection == "wop"):
                            self.__tcl_string.append(self.__code_exec.run_sim_attacked())
                        elif(self.__protection == "hamming"):
                            self.__tcl_string.append(self.__code_exec.run_sim_attacked_hamming())
                        self.__tcl_string.append(self.__log_data.log_sim(threat="multi_bitflip_reg_multi"))
                        self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
                        try:
                            self.write_tcl_file(''.join(self.__tcl_string))
                        except TypeError as e:
                            print("TypeError happened -- multi_bitflip_reg_multi\n", e)
                            exit(1)
                        if(self.__nb_simu >= (self.__batch_max_sim * self.__batch_number)):
                            self.__batch_number += 1
                            self.gen_new_file(window)

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
                    exit(2)
            for reg in registers:
                for data_reg in registers[reg]:
                    name_regs.append(data_reg['name'])
                    size_regs.append(data_reg['width'])
        except FileNotFoundError:
            print(f"File registers_{self.__protection}.yaml not found. Please check the installation.")
            print("Exiting generation ...")
            exit(1)
        self.__registers_list = name_regs
        self.__registers_size = size_regs
        return 0
    
    def write_faulted_registers_file(self):
        """Create the faulted registers file in the simulation folder."""
        try:
            with open(self.__gen_path + "faulted_regs.yaml", 'w') as file:
                yaml.dump(self.__registers_list, file, default_flow_style=False)
        except Exception as e:
            print("An exception has occurred : {exc}".format(exc=e.args[1]))
            return 1
        return 0
            
    def gen_build_make(self):
        """Generate the simulation compilation string to be copied in build.make to simulate the simulations in 1 line"""
        if not self.__build_make_list:
            return  # Nothing to do if build_make_list is empty
        nb_simu_files = math.ceil(self.__nb_files / self.__config_data_simulator['multi_res_files'][self.__code])
        build_make_str = ""
        try:
            with open(self.__gen_path + "build.make", 'w') as build_file:
                for index, elem in enumerate(self.__build_make_list):
                    if index % nb_simu_files == 0 and index != 0:
                        build_make_str += f"\n\ncd /home/william/Documents/DRiSCY/pulpino/sw/build/apps/{self.__code}"
                    elif index % nb_simu_files == 0 and index == 0:
                        build_make_str += f"cd /home/william/Documents/DRiSCY/pulpino/sw/build/apps/{self.__code}"

                    build_make_str += " && tcsh -c env\ PULP_CORE=riscv\ VSIM_DIR=/home/william/Documents/DRiSCY/pulpino/vsim\ TB_TEST=""\ /home/william/tools_memphis/questa/questasim/linux_x86_64/vsim\ -c\ -64\ -do\ 'source\ tcl_files/run.tcl\;\ {elem}\;\ exit\;'\ > vsim.log".format(elem=elem)
                build_file.write(build_make_str)
        except Exception as e:
            print("An exception occurred: {exc}".format(exc=e.args[1]))
            return 1
        return 0