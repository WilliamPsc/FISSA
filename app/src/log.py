"""
## @Author : William PENSEC
## @Version : 0.0
## @Date : 07 février 2023
## @Description : Log data depending of the simulator
"""

### Import packages ###


### Class ###
class LogData:
    def __init__(self, config_data):
        self.__simulator = config_data["name_simulator"]
        # Ajout des chemins vers csr, tpr, tcr, rf, rft, ....

    # def log_sim(self, nb_file = 1):
    #     match self.__simulator:
    #         case "modelsim":
    #             return self.log_data_modelsim(nb_file)
    #         case "xsim":
    #             pass
    #         case "verilator":
    #             pass
    #         case _:
    #             return ""
            
    def log_sim(self, nb_file = 1, threat = ""):
        match threat:
            case "simu0":
                return self.__log_data_simu0(nb_file)
            case "set0":
                return self.__log_data_set0()
            case "set1":
                return self.__log_data_set1()
            case "bitflip":
                return self.__log_data_bitflip()
            case "multi_bitflip_spatial":
                return self.__log_data_multi_bitflip_spatial(nb_file)
            case "multi_bitflip_temporel":
                pass
            case _:
                return ""

    def log_data_modelsim(self, nb_file = 1):
        # insérer tcl list avoid registers + insérer log_paths du fichier de config
        if(nb_file == 1):
            return """
#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\\t\\"simulation_$nb_sim\\": {"

#---- Cycle Checking ----
puts $f "\\t\\t\\"cycle_ref\\": $cycle_ref," 
puts $f "\\t\\t\\"cycle_ending\\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\\t\\t\\"TPR\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\\","
puts $f "\\t\\t\\"TCR\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"rf$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"rf_tag$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\\": \\"[examine -hex $reg]\\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\\t\\t\\"faulted_register\\": \\"$faulted_register\\","
    puts $f "\\t\\t\\"size_faulted_register\\": $width_threat,"
    puts $f "\\t\\t\\"threat\\": \\"$threat\\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\\t\\t\\"bit_flipped\\": $bit_flipped,"
    }
    puts $f "\\t\\t\\"cycle_attacked\\": \\"$start_sim\\","
}
 
#---- Ending status ----
puts $f "\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\"status_end\\": $status_end"
puts $f "\\t},"

#---- Close log ----
close $f
"""
        else:
            return ""

    def __log_data_simu0(self, nb_file = 1):
        if(nb_file == 1):
            return """
#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\\t\\"simulation_$nb_sim\\": {"

#---- Cycle Checking ----
puts $f "\\t\\t\\"cycle_ref\\": $cycle_ref," 
puts $f "\\t\\t\\"cycle_ending\\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\\t\\t\\"TPR\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\\","
puts $f "\\t\\t\\"TCR\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"rf$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"rf_tag$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\\": \\"[examine -hex $reg]\\","
    }
}
 
#---- Ending status ----
puts $f "\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\"status_end\\": $status_end"
puts $f "\\t},"

#---- Close log ----
close $f
"""
        else:
            return "" 
        
    def __log_data_set0(self):
        pass

    def __log_data_set1(self):
        pass

    def __log_data_bitflip(self):
        pass

    def __log_data_multi_bitflip_spatial(self, nb_file = 1):
        if(nb_file == 1):
            return """
#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\\t\\"simulation_$nb_sim\\": {"

#---- Cycle Checking ----
puts $f "\\t\\t\\"cycle_ref\\": $cycle_ref," 
puts $f "\\t\\t\\"cycle_ending\\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\\t\\t\\"TPR\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\\","
puts $f "\\t\\t\\"TCR\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"rf$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"rf_tag$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\\": \\"[examine -hex $reg]\\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\\t\\t\\"threat\\": \\"$threat\\","
    puts $f "\\t\\t\\"cycle_attacked\\": \\"$start_sim\\","
    # Faulted register 0
    puts $f "\\t\\t\\"faulted_register_0\\": \\"$faulted_register_0\\","
    puts $f "\\t\\t\\"size_faulted_register_0\\": $width_register_0,"
    puts $f "\\t\\t\\"bit_flipped_0\\": $bit_flipped_0,"

    # Faulted register 1
    puts $f "\\t\\t\\"faulted_register_1\\": \\"$faulted_register_1\\","
    puts $f "\\t\\t\\"size_faulted_register_1\\": $width_register_1,"
    puts $f "\\t\\t\\"bit_flipped_1\\": $bit_flipped_1,"
}
 
#---- Ending status ----
puts $f "\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\"status_end\\": $status_end"
puts $f "\\t},"

#---- Close log ----
close $f
"""
        else:
            return ""