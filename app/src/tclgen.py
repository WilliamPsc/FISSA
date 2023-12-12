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
        self.__config_data_simulator = config_data
        self.__sim_path = config_data["path_tcl_generation"]
        self.__name_simulator = config_data["name_simulator"]
        self.__files_sim = config_data["path_files_sim"]
        self.__threat_model = config_data['threat_model']
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
    def nb_simu(self):
        '''Return the number of simulations to be done'''
        return self.__nb_simu_total

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

    # @nb_simu.setter
    def set_nb_simu_total(self, threat_model:list, window:list):
        '''Set number of simulations to be done'''
        for threat in threat_model:
            if(threat == "set0"):
                self.__nb_simu_total += (len(self.__registers_list) * int((window[1] - window[0]) / 40))
            elif(threat == "set1"):
                self.__nb_simu_total += (len(self.__registers_list) * int((window[1] - window[0]) / 40))
            elif(threat == "bitflip"):
                self.__nb_simu_total += (sum(self.__registers_size) * int((window[1] - window[0]) / int(self.__config_data_simulator['cpu_period'])))
            elif(threat == "multi_bitflip_spatial"):
                pass
            elif(threat == "multi_bitflip_temporel"):
                pass
            else:
                pass

    ## Fonction servant à construire la chaîne de simulation
    def build_data_string(self):
        """Function used to build the simulation TCL string"""
        path_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "-" + self.__protection + "_" + '-'.join(self.__threat_model) + "/"
        reg_file_sim = path_file_sim + "faulted_regs.yaml"
        for window in self.__config_data_simulator['fenetre_tir'][self.__code]:
            self.set_nb_simu_total(self.__config_data_simulator["threat_model"], window)
            print(f"Number of simulations to be run : {self.__nb_simu_total}")
            file_number = 1
            if(self.__nb_simu_total < self.__batch_max_sim):
                nb_files = math.ceil(self.__nb_simu_total / self.__batch_max_sim)
                print("Nombre de fichiers à générer :", nb_files)
                file_str = "source\ " + str(path_file_sim) + str(self.__code) + "_" + str(self.__protection) + "_" + str(file_number) + ".tcl"
                self.build_make_list = file_str
                self.__tcl_file = self.__res_path + self.__code + "_" + self.__protection + "_" + str(file_number) + ".tcl"
                log_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "-" + self.__protection + "_" + '-'.join(self.__threat_model) + "/" + self.__code + "-" + self.__protection + "_" + str(file_number) + ".json"
                self.build_ref_sim(reg_file_sim, log_file_sim, window, self.__nb_simu_total, 1)
                self.build_simus(window, self.__nb_simu_total, self.__batch_max_sim)
            else:
                nb_files = math.ceil(self.__nb_simu_total / self.__batch_max_sim)
                print("Nombre de fichiers à générer :", nb_files)
                for i in range(nb_files):
                    if(file_number != -1):
                        file_str = "source\ " + str(path_file_sim) + str(self.__code) + "_" + str(self.__protection) + "_" + str(file_number) + ".tcl"
                        self.build_make_list = file_str
                        self.__tcl_file = self.__res_path + self.__code + "_" + self.__protection + "_" + str(file_number) + ".tcl"
                        log_file_sim = ''.join(self.__config_data_simulator['path_simulation']).replace('__code', self.__code) + "-" + self.__protection + "_" + '-'.join(self.__threat_model) + "/" + self.__code + "-" + self.__protection + ".json"
                        self.build_ref_sim(reg_file_sim, log_file_sim, window, self.__nb_simu_total, file_number)
                        file_number = self.build_simus(window, self.__nb_simu_total, self.__batch_max_sim)
        self.gen_build_make()
            
    def build_ref_sim(self, reg_file_sim, log_file_sim, fenetre, nb_simulations, nb_file = 1):
        self.__tcl_string = list()
        self.__tcl_string.append(self.__code_exec.init_sim(reg_file_sim, log_file_sim, nb_file))
        self.__tcl_string.append(self.__code_exec.init_tcl_variables(fenetre))
        self.__tcl_string.append(self.__code_exec.gen_simu_ref())
        self.__tcl_string.append(self.__code_exec.run_simu_ref())
        self.__tcl_string.append(self.__log_data.log_sim(nb_file))
        self.__tcl_string.append(self.__code_exec.end_sim(0,nb_simulations))
        self.write_tcl_file(''.join(self.__tcl_string))
     
    def build_simus(self, fenetre, nb_simulations, nb_simu_max_batch):
        self.__tcl_string = list()
        for reg in self.__registers_list: # attention lorsqu'un registre est un tableau de plusieurs bits
            if (reg not in self.__config_data_simulator['avoid_register']):
                for threat in self.__threat_model:
                    if(threat == "bitflip"):
                        for wreg in range(self.__registers_size[self.__registers_list.index(reg)]):
                            for start_time in range(fenetre[0], fenetre[1], 40):
                                self.__tcl_string = list()
                                self.__nb_simu += 1
                                self.__tcl_string.append(self.__code_exec.init_sim_attacked(self.__nb_simu, start_time, threat, reg, self.__registers_size[self.__registers_list.index(reg)]))
                                self.__tcl_string.append(self.__inject_fault.inject_fault(threat, wreg))
                                self.__tcl_string.append(self.__code_exec.run_sim_attacked())
                                self.__tcl_string.append(self.__log_data.log_sim())
                                self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
                                try:
                                    self.write_tcl_file(''.join(self.__tcl_string))
                                except TypeError as e:
                                    print("TypeError")
                                    return -1
                                if(self.__nb_simu >= (nb_simu_max_batch * self.__batch_number)):
                                    self.__batch_number += 1
                                    return self.__batch_number
                                if(self.__nb_simu >= nb_simulations):
                                    return -1
                    else:
                        for start_time in range(fenetre[0], fenetre[1], 40):
                            self.__tcl_string = list()
                            self.__nb_simu += 1
                            self.__tcl_string.append(self.__code_exec.init_sim_attacked(self.__nb_simu, start_time, threat, reg, self.__registers_size[self.__registers_list.index(reg)]))
                            self.__tcl_string.append(self.__inject_fault.inject_fault(threat))
                            self.__tcl_string.append(self.__code_exec.run_sim_attacked())
                            self.__tcl_string.append(self.__log_data.log_sim())
                            self.__tcl_string.append(self.__code_exec.end_sim(self.__nb_simu, nb_simulations))
                            try:
                                self.write_tcl_file(''.join(self.__tcl_string))
                            except TypeError:
                                print(self.__nb_simu, self.__tcl_file, nb_simulations, nb_simu_max_batch)
                                print(self.__tcl_string)
                                return -1
                            if(self.__nb_simu >= (nb_simu_max_batch * self.__batch_number)):
                                self.__batch_number += 1
                                return self.__batch_number
                            if(self.__nb_simu >= nb_simulations):
                                return -1

    def build_faulted_simu(self):
        for threat in self.__threat_model:
            if(threat == "multi_bitflip_spatial"):
                self.build_multi_bitflip_spatial()
            if(threat == "multi_bitflip_temporel"):
                self.build_multi_bitflip_temporel()

            match threat:
                case "set0":
                    self.build_bit_reset_simu()
                case "set1":
                    self.build_bit_set_simu()
                case "bitflip":
                    self.build_bitflip_simu()
                case _:
                    print("Unknown threat model. You forgot to define it.")

    def build_bit_set_simu(self):
        for reg in self.__registers_list:
            if(reg not in self.__config_data_simulator['avoid_register']):
                pass

    def build_bit_reset_simu(self):
        pass

    def build_bitflip_simu(self):
        pass

    def build_multi_bitflip_spatial(self):
        pass

    def build_multi_bitflip_temporel(self):
        pass

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
            pyperclip.copy(str_to_clipboard)