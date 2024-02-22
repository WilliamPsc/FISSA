"""
# @Author : William PENSEC
# @Version : 1.0
# @Date : 07 février 2024
# @DateVersion : 07 février 2024
# @Description : 
"""

### Import packages ###
## General modules ##
import math
import os
import pathlib
import yaml
from src.code_execution import CodeExecute
from src.fault_injection import FaultInjection
from src.log import LogData
## Custom modules ##
from src.tclgen import TCL

### MAIN CLASS ###
class PerformancesComparison:
    """
    Class to allow the test of performances with and without fault injection to measure the overhead induced by the script generated
    """
    def __init__(self, protect = "wop"):  
        """ Set all necessary file paths & define variables """
        self.__protection = protect
        self.__app_folder = pathlib.Path(__file__).resolve().parent.parent
        self.__config_folder = pathlib.Path.joinpath(self.__app_folder, "config")
        self.__config_file_path = str(self.__config_folder) + "/config_" + self.__protection + ".json"
        self.read_config()
        self.__log_data = LogData(self.__config_data)
        self.__inject_fault = FaultInjection(self.__config_data)
        self.__files_sim = self.__config_data["path_files_sim"]
        self.__code = self.get_codes()[0]
        self.__gen_path = self.__config_data["path_generated_sim"] + self.__code + "/" + self.__code + "_" + self.__protection + "_performance_comparison/"
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

        self.__res_path = self.__config_data["path_results_sim"] + self.__code + "/" + self.__code + "_" + self.__protection + "_performance_comparison/"
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
        self.__batch_max_sim:int = self.__config_data["batch_sim"]
        self.__build_make_list = list()

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
            with open(self.__gen_path + "faulted_regs.yaml", 'w') as file:
                yaml.dump(self.__registers_list, file, default_flow_style=False)
        except Exception as e:
            print("An exception has occurred : {exc}".format(exc=e.args[1]))
            return 1
        return 0
    
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
    
    def gen_build_make(self):
        """Generate the simulation compilation string to be copied in build.make to simulate the simulations in 1 line"""
        if not self.__build_make_list:
            return  # Nothing to do if build_make_list is empty
        nb_simu_files = math.ceil(self.__nb_files / self.__config_data['multi_res_files'])
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

    def build_data_string(self, nb_repetitions:int):
        """Function used to build the simulation TCL string"""
        print("\t===============", self.__config_data['name_results'][self.__code], "===============")
        self.__path_file_sim = ''.join(self.__config_data['path_simulation']).replace('__code', self.__code) + "_" + self.__protection + "_performance_comparison/"
        self.__reg_file_sim = self.__path_file_sim + "faulted_regs.yaml"
        self.__file_number = 1
        window = self.__config_data['fenetre_tir'][self.__code][0]

        print(f"\t\t >>>> Number of simulations to execute: {nb_repetitions}")
        self.__nb_files = math.ceil(nb_repetitions / self.__batch_max_sim) * 2
        print("\t\t >>>> Number of files to generate:", self.__nb_files)

        ## Generate reference simulation ##
        file_str = "source\ " + str(self.__path_file_sim) + self.__code + "_" + self.__protection + "_performance_comparison_" + str(self.__file_number) + ".tcl"
        self.build_make_list = file_str
        log_file_sim = str(self.__path_file_sim) + "results/" + self.__protection + "_performance_comparison_" + str(self.__file_number) + ".json"
        self.__tcl_file = self.__gen_path + self.__code + "_" + self.__protection + "_performance_comparison_" + str(self.__file_number) + ".tcl"
        self.generate_test_simu0(nb_repetitions, log_file_sim, window, 1)

        ## Generate faulted simulations ##
        self.__file_number = 2
        file_str = "source\ " + str(self.__path_file_sim) + self.__code + "_" + self.__protection + "_performance_comparison_" + str(self.__file_number) + ".tcl"
        self.build_make_list = file_str
        log_file_sim = str(self.__path_file_sim) + "results/" + self.__protection + "_performance_comparison_" + str(self.__file_number) + ".json"
        self.__tcl_file = self.__gen_path + self.__code + "_" + self.__protection + "_performance_comparison_" + str(self.__file_number) + ".tcl"
        self.build_test_faulted_simu(nb_repetitions, log_file_sim, window, 1)

        ## Generate build file ##
        self.gen_build_make()
    
    def get_codes(self):
        return self.__config_data['codes']
    
    def generate_test_simu0(self, nb_repetitions:int, log_file_sim, window, nb_file):
        for nb_rep in range(nb_repetitions + 1):
            self.__tcl_string = list()
            self.__tcl_string.append(self.__init_sim(self.__reg_file_sim , log_file_sim, nb_rep))
            self.__tcl_string.append(self.__init_tcl_variables(window, nb_rep))
            self.__tcl_string.append(self.__gen_simu_ref(nb_rep))
            self.__tcl_string.append(self.__run_simu_ref(nb_rep))
            self.__tcl_string.append(self.__log_data.log_sim(nb_file, threat="simu0"))
            self.__tcl_string.append(self.__end_sim(nb_rep,nb_repetitions))
            try:
                self.write_tcl_file(''.join(self.__tcl_string))
            except TypeError:
                print("TypeError simu 0 happened")
                exit(1)

    def build_test_faulted_simu(self, nb_repetitions:int, log_file_sim, window, nb_file):
        nb_rep = 0
        self.__tcl_string = list()
        self.__tcl_string.append(self.__init_sim(self.__reg_file_sim , log_file_sim, nb_rep))
        self.__tcl_string.append(self.__init_tcl_variables(window, nb_rep))
        self.__tcl_string.append(self.__gen_simu_ref(nb_rep))
        self.__tcl_string.append(self.__run_simu_ref(nb_rep))
        self.__tcl_string.append(self.__log_data.log_sim(nb_file, threat="simu0"))
        self.__tcl_string.append(self.__end_sim(nb_rep,nb_repetitions))
        try:
            self.write_tcl_file(''.join(self.__tcl_string))
        except TypeError:
            print("TypeError simu 0 happened")
            exit(1)

        for reg in self.__registers_list:
            if(reg not in self.__config_data['avoid_register'] and nb_rep < nb_repetitions):
                for wreg in range(self.__registers_size[self.__registers_list.index(reg)]):
                    for start_time in range(window[0], window[1], 40):
                        if(nb_rep < nb_repetitions):
                            self.__tcl_string = list()
                            nb_rep += 1
                            self.__tcl_string.append(self.__init_sim_attacked(nb_rep, start_time, "bitflip", reg, self.__registers_size[self.__registers_list.index(reg)]))
                            self.__tcl_string.append(self.__inject_fault.inject_fault("bitflip", wreg, size_reg_0=self.__registers_size[self.__registers_list.index(reg)]))
                            self.__tcl_string.append(self.__run_sim_attacked())
                            self.__tcl_string.append(self.__log_data.log_sim(threat="bitflip"))
                            self.__tcl_string.append(self.__end_sim(nb_rep, nb_repetitions))
                            try:
                                self.write_tcl_file(''.join(self.__tcl_string))
                            except TypeError:
                                print("TypeError bit-flip happened")
                                exit(1)
                        else:
                            break
        

#########################################################################################################################
    ### Generate simulations ###
    def __init_sim(self, reg_file, log_file, nb_sim):
        if(nb_sim == 0):
            return """############# INIT SIMULATIONS #############
set regs_file {regs_file}
set state_file {state_file}
set f [open $state_file w]
puts $f "{{"
puts $f "\\t\\"start\\": \\"[clock format [clock seconds] -format \"%Y/%m/%d:%H:%M:%S\"]\\","
close $f

set f [open $regs_file r]
set reg_file_data [read $f]
close $f
""".format(regs_file = reg_file, state_file = log_file)
        else:
            return ""
        
    def __init_tcl_variables(self, start_window, nb_sim):
        log_registers = ""
        for reg in self.__config_data['avoid_log_registers']:
            log_registers += str(reg) + " "
        return """
###### INIT VARIABLES ######
### CONTROL ###
set periode {periode}
set half_periode [expr {{$periode / 2}}]

set start {start_ns}
set nb_sim {number} ;# Simulation number
set sim_active 1 ;# Active sim Boolean
set cycle_ref {init_cycle} ;# Setting the number of reference cycles for the complete simulation
set cycle_curr 0
set log_registers_list {{{log_reg}}}

### FAULTED REGISTER ###
set threat ""
set width_register 0
set faulted_register ""

### DETECTED ERRORS ###
set value_end_pc 0
set cycle_ill_insn ""

### STATUS END ###
set status_end -1 ;# End of simulation code (0: reference simulation / 1: reference cycle number exceeded (crash) / 2: jump to illegal instruction handler (identical to reference simulation) / 3: jump to illegal instruction handler (delayed) / 4: success / 5: error detected / ...)
""".format(start_ns=int((start_window[0] + start_window[1]) / 2), init_cycle=self.__config_data['cycle_ref'], log_reg = log_registers, periode = self.__config_data['cpu_period'], number=nb_sim)

    def __gen_simu_ref(self, nb_sim):
        return """
############# ATTACK {number} #############
###### JUMP TO ATTACK START ######
run "$start ns"
""".format(number=nb_sim)

    def __run_simu_ref(self, nb_sim):
        if(nb_sim == 0):
            return """
##---------------------
while {$cycle_curr <= $cycle_ref} {
    incr cycle_curr
    run "$periode ns"
    set value_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]
    set value_insn_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/instr_rdata_id_o]
    if {([expr {$value_pc} == {"32'h0000022c"}]) && ([expr {$value_insn_pc} == {"32'hfa010113"}])} {
        set cycle_ill_insn [expr $now / 1000]
    }
}

############# CHECKING SIM VALUES #############
## CHECK ENDING CYCLE ##
set check_cycle [expr [expr $now / 1000 - $start] / 40] ;# Vérification du numéro du cycle actuel
set value_end_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]
set status_end 0
set cycle_curr 0
"""
        else:
            return """
###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
while {$sim_active == 1} {
    run "$periode ns" ;# run 1 cycle
    incr nb_cycle

    set value_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]

    ############# CHECKING SIM VALUES #############
    ## if conditions to stop the run cycles
    if {$nb_cycle > $cycle_ref} {
        ## CYCLE OVERFLOW : CRASH ##
        set sim_active 0
        set status_end 1
    } elseif {([expr {$value_pc} == {"32'h0000022c"}]) && ([expr {[examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/instr_rdata_id_o]} == {"32'hfa010113"}])} {
        ## INSN ILL HANDLER ##
        if {[expr {$cycle_ill_insn} == {[expr $now / 1000]}]} {
            # Illegal insn handler au même moment que simulation 0  : NOTHING #
            set status_end 2
        } else {
            # Illegal insn handler à un moment différent que simulation 0 : EXCEPTION DECALEE #
            set status_end 3
        }
        set sim_active 0
    } elseif {($nb_cycle == $cycle_ref) && ([expr {$value_pc} == {$value_end_pc}])} {
        ## RAS ##
        set status_end 0
        set sim_active 0
    } elseif {($nb_cycle == $cycle_ref) && ([expr {$value_pc} != {$value_end_pc}])} {
        ## SUCCESS ? ##
        set status_end 4
        set sim_active 0
    }
}
"""

    def __init_sim_attacked(self, nb_sim, start_time, threat, register, size_register = 1):
        return """
##############################################################################
############# ATTACK {number} #############
set nb_sim {number}
puts "Simulation number : $nb_sim"
###### JUMP TO ATTACK START ######
set start_sim "{start_window} ns"
run "{start_window} ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr {start_window} - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "{faute}"
set width_register {width_register}
set faulted_register {reg}
set bit_flipped -1

### STATUS END ###
set status_end -1 
""".format(number = nb_sim, start_window = start_time, faute = threat, width_register = size_register, reg = register)

    def __run_sim_attacked(self):
        return """
###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
while {$sim_active == 1} {
    run "$periode ns" ;# run 1 cycle
    incr nb_cycle

    set value_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]

    ############# CHECKING SIM VALUES #############
    ## if conditions to stop the run cycles
    if {$nb_cycle > $cycle_ref} {
        ## CYCLE OVERFLOW : CRASH ##
        set sim_active 0
        set status_end 1
    } elseif {([expr {$value_pc} == {"32'h0000022c"}]) && ([expr {[examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/instr_rdata_id_o]} == {"32'hfa010113"}])} {
        ## INSN ILL HANDLER ##
        if {[expr {$cycle_ill_insn} == {[expr $now / 1000]}]} {
            # Illegal insn handler au même moment que simulation 0  : NOTHING #
            set status_end 2
        } else {
            # Illegal insn handler à un moment différent que simulation 0 : EXCEPTION DECALEE #
            set status_end 3
        }
        set sim_active 0
    } elseif {($nb_cycle == $cycle_ref) && ([expr {$value_pc} == {$value_end_pc}])} {
        ## RAS ##
        set status_end 0
        set sim_active 0
    } elseif {($nb_cycle == $cycle_ref) && ([expr {$value_pc} != {$value_end_pc}])} {
        ## SUCCESS ? ##
        set status_end 4
        set sim_active 0
    }
}
"""

    def __end_sim(self, nbSimCurr, nbSimusTotal):
        if nbSimCurr < nbSimusTotal - 1:
            return """
############# END SIM {number} #############
# Restart the simulation
restart
#------------------------------------\n""".format(number = nbSimCurr)
        elif nbSimCurr == nbSimusTotal - 1:
            return """
############# END SIM {number} #############
# Write date of end
set f [open $state_file a]
puts $f "\\"end\\": \\"[clock format [clock seconds] -format "%Y/%m/%d:%H:%M:%S"]\\""
puts $f "}}"
close $f

# Exit the simulation
exit
#------------------------------------""".format(number = nbSimCurr)
        elif nbSimCurr == nbSimusTotal:
            return """
############# END SIM {number} #############
# Write date of end
set f [open $state_file a]
puts $f "\\"end\\": \\"[clock format [clock seconds] -format "%Y/%m/%d:%H:%M:%S"]\\""
puts $f "}}"
close $f

# Exit the simulation
exit
#------------------------------------""".format(number = nbSimCurr)