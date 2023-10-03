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
        self._simulator = config_data["name_simulator"]
        self._tcr = config_data['log_paths']['tcr']
        self._tpr = config_data['log_paths']['tpr']
        self._rf_reg = config_data['log_paths']['rf']
        self._rf_reg_tag = config_data['log_paths']['rf_tag']
        # Ajout des chemins vers csr, tpr, tcr, rf, rft, ....

    def log_sim(self, start_sim:bool):
        match self._simulator:
            case "modelsim":
                if(start_sim):
                    return self.log_curr_modelsim()
                else:
                    return self.log_data_modelsim()
            case "xsim":
                pass
            case "verilator":
                pass
            case _:
                return ""


    def log_curr_modelsim(self):
        return """
#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\\t\\"simulation_$nb_sim\\": {{"
puts $f "\\t\\t\\"start_status\\": {{"

#---- TCR / TPR ----
puts $f "\\t\\t\\t\\"TPR\\": \\"[examine -hex {tpr_q}]\\","
puts $f "\\t\\t\\t\\"TCR\\": \\"[examine -hex {tcr_q}]\\","

#---- Log Register File ----
for {{set j 0}} {{$j < 32}} {{incr j}} {{
    puts $f "\\t\\t\\t\\"rf$j\\": \\"[examine -hex {rf_reg}\[{{$j}}\]]\\","
}}

#---- Log Register File Tag ----
for {{set j 0}} {{$j < 32}} {{incr j}} {{
    puts $f "\\t\\t\\t\\"rf_tag$j\\": \\"[examine -hex {rf_reg_tag}\[{{$j}}\]]\\","
}}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {{
    foreach avoid_reg $log_registers_list {{
        if {{[expr {{$reg != "-"}}]
            && ([expr [lsearch -regexp $log_registers_list $reg] == -1]
            && ![string match "$avoid_reg*" $reg])
        }} {{
            set nom_reg_list [split $reg "/"]
            puts $f "\\t\\t\\t\\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\\": \\"[examine -hex $reg]\\","
            return -level 1 code break
        }}
    }}
}}

#---- Log faulted register: name, width, threat considered, when ----
if {{$nb_sim != 0}} {{
    puts $f "\\t\\t\\t\\"faulted_register\\": \\"$faulted_register\\","
    puts $f "\\t\\t\\t\\"size_faulted_register\\": $width_threat,"
    puts $f "\\t\\t\\t\\"threat\\": \\"$threat\\","
    if {{[expr {{$threat == "bitflip"}}]}} {{
        puts $f "\\t\\t\\t\\"bit_flipped\\": $bit_flipped,"
    }}
}}
 
#---- Ending status ----
puts $f "\\t\\t\\t\\"simulation_current_time\\": \\"[expr {{$now / 1000}}] ns\\""
puts $f "\\t\\t}},"

#---- Close log ----
close $f
""".format(tpr_q = self._tpr, tcr_q = self._tcr, rf_reg = self._rf_reg, rf_reg_tag = self._rf_reg_tag)

    def log_data_modelsim(self, ):
        # insérer tcl list avoid registers + insérer log_paths du fichier de config
        return """
#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\\t\\t\\"end_status\\": {"

#---- Cycle Checking ----
puts $f "\\t\\t\\t\\"cycle_ref\\": $cycle_ref," 
puts $f "\\t\\t\\t\\"cycle_ending\\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\\t\\t\\t\\"TPR\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\\","
puts $f "\\t\\t\\t\\"TCR\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\t\\"rf$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\\t\\t\\t\\"rf_tag$j\\": \\"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {$reg != "/tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q"}]
        && [expr {$reg != "/tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q"}]
        && ![string match "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg*" $reg])
        && [expr {$reg != "-"}]
    } {
        set nom_reg_list [split $reg "/"]
        puts $f "\\t\\t\\t\\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\\": \\"[examine -hex $reg]\\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\\t\\t\\t\\"faulted_register\\": \\"$faulted_register\\","
    puts $f "\\t\\t\\t\\"size_faulted_register\\": $width_threat,"
    puts $f "\\t\\t\\t\\"threat\\": \\"$threat\\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\\t\\t\\t\\"bit_flipped\\": $bit_flipped,"
    }
    puts $f "\\t\\t\\t\\"cycle_attacked\\": \\"$start_sim\\","
}
 
#---- Ending status ----
puts $f "\\t\\t\\t\\"simulation_end_time\\": \\"[expr {$now / 1000}] ns\\","
puts $f "\\t\\t\\t\\"status_end\\": $status_end"
puts $f "\\t\\t}"
puts $f "\\t},"

#---- Close log ----
close $f
"""