"""
## @Author : William PENSEC
## @Version : 1.0
## @Date : 07 February 2023
## @DateVersion : 08 April 2024
## @Description : Log data depending of the simulator
"""

### Import packages ###


### Class ###
class LogData:
    def __init__(self, config_data):
        self.__simulator = config_data["name_simulator"]

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
            case "single_bitflip_spatial":
                return self.__log_data_single_bitflip_spatial()
            case "single_bitflip_temporel":
                return self.__log_data_single_bitflip_temporel()
            case "multi_bitflip_reg":
                return self.__log_data_multi_bitflip_reg()
            case "multi_bitflip_reg_multi":
                return self.__log_data_multi_bitflip_reg_multi()
            case _:
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

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"registers_i/rf$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
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
        """"""
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

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\\": \\"[examine -hex $reg]\\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
puts $f "\\t\\t\\"threat\\": \\"$threat\\","
puts $f "\\t\\t\\"cycle_attacked\\": \\"$start_sim\\","
# Faulted register 0
puts $f "\\t\\t\\"faulted_register\\": \\"$faulted_register\\","
puts $f "\\t\\t\\"size_faulted_register\\": $width_register,"
 
#---- Ending status ----
puts $f "\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\"status_end\\": $status_end"
puts $f "\\t},"

#---- Close log ----
close $f
"""

    def __log_data_set1(self):
        """"""
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

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\\": \\"[examine -hex $reg]\\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
puts $f "\\t\\t\\"threat\\": \\"$threat\\","
puts $f "\\t\\t\\"cycle_attacked\\": \\"$start_sim\\","
# Faulted register 0
puts $f "\\t\\t\\"faulted_register\\": \\"$faulted_register\\","
puts $f "\\t\\t\\"size_faulted_register\\": $width_register,"
 
#---- Ending status ----
puts $f "\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\"status_end\\": $status_end"
puts $f "\\t},"

#---- Close log ----
close $f
"""

    def __log_data_bitflip(self):
        """"""
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

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\\": \\"[examine -hex $reg]\\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\\t\\t\\"threat\\": \\"$threat\\","
    puts $f "\\t\\t\\"cycle_attacked\\": \\"$start_sim\\","
    # Faulted register 0
    puts $f "\\t\\t\\"faulted_register\\": \\"$faulted_register\\","
    puts $f "\\t\\t\\"size_faulted_register\\": $width_register,"
    puts $f "\\t\\t\\"bit_flipped\\": $bit_flipped,"
}
 
#---- Ending status ----
puts $f "\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\"status_end\\": $status_end"
puts $f "\\t},"

#---- Close log ----
close $f
"""

    def __log_data_single_bitflip_spatial(self):
            """"""
            return """
#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\\t\\"simulation_$nb_sim\\": {"

#---- Cycle Checking ----
puts $f "\\t\\t\\"cycle_ref\\": $cycle_ref," 
puts $f "\\t\\t\\"cycle_ending\\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"rf$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
    }
}

foreach reg $log_registers_list {
    set nom_reg_list [split $reg "/"]
    puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
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
        
    def __log_data_single_bitflip_temporel(self):
        """"""
        return """
#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\\t\\"simulation_$nb_sim\\": {"

#---- Cycle Checking ----
puts $f "\\t\\t\\"cycle_ref\\": $cycle_ref," 
puts $f "\\t\\t\\"cycle_ending\\": $check_cycle,"

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\"rf$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
    }
}

foreach reg $log_registers_list {
    set nom_reg_list [split $reg "/"]
    puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\\t\\t\\"threat\\": \\"$threat\\","
    # Faulted register 0
    puts $f "\\t\\t\\"cycle_attacked_0\\": \\"$time_fault_register_0\\","
    puts $f "\\t\\t\\"faulted_register_0\\": \\"$faulted_register_0\\","
    puts $f "\\t\\t\\"size_faulted_register_0\\": $width_register_0,"
    puts $f "\\t\\t\\"bit_flipped_0\\": $bit_flipped_0,"

    # Faulted register 1
    puts $f "\\t\\t\\"cycle_attacked_1\\": \\"$time_fault_register_1\\","
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
        
    def __log_data_multi_bitflip_reg(self):
        """"""
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

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
    }
}

foreach reg $log_registers_list {
    set nom_reg_list [split $reg "/"]
    puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\\t\\t\\"threat\\": \\"$threat\\","
    puts $f "\\t\\t\\"cycle_attacked\\": \\"$start_sim\\","
    # Faulted register 0
    puts $f "\\t\\t\\"faulted_register\\": \\"$faulted_register\\","
    puts $f "\\t\\t\\"size_faulted_register\\": $width_register,"
    puts $f "\\t\\t\\"value_set\\": \\"$bit_flipped\\","
}
 
#---- Ending status ----
puts $f "\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\"status_end\\": $status_end"
puts $f "\\t},"

#---- Close log ----
close $f
"""

    def __log_data_multi_bitflip_reg_multi(self):
        """"""
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

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $avoid_log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
    }
}

foreach reg $log_registers_list {
    set nom_reg_list [split $reg "/"]
    puts $f "\\t\\t\\"[join [lrange $nom_reg_list end-1 end] "/"]\\": \\"[examine -hex $reg]\\","
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\\t\\t\\"threat\\": \\"$threat\\","
    puts $f "\\t\\t\\"cycle_attacked\\": \\"$start_sim\\","
    # Faulted register 0
    puts $f "\\t\\t\\"faulted_register_0\\": \\"$faulted_register_0\\","
    puts $f "\\t\\t\\"size_faulted_register_0\\": $width_register_0,"
    puts $f "\\t\\t\\"value_set_0\\": \\"$bit_flipped_0\\","

    # Faulted register 1
    puts $f "\\t\\t\\"faulted_register_1\\": \\"$faulted_register_1\\","
    puts $f "\\t\\t\\"size_faulted_register_1\\": $width_register_1,"
    puts $f "\\t\\t\\"value_set_1\\": \\"$bit_flipped_1\\","
}
 
#---- Ending status ----
puts $f "\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\"status_end\\": $status_end"
puts $f "\\t},"

#---- Close log ----
close $f
"""