"""
## @Author : William PENSEC
## @Version : 0.1
## @Date : 19 janvier 2023
## @Description : 
"""

### Import packages ###

### Class ###
class CodeExecute:
    """Generate TCL strings to create script"""

    ## Class constructor
    # def __init__(self, config_data):
    def __init__(self, config_data:dict, code:str):
        self.__config_data = config_data
        self.__code = code
        self.__cycle_ref = self.__config_data['cycle_ref']
        if(self.__config_data['multi_res_files'][self.__code] < 1):
            self.__config_data['multi_res_files'][self.__code] = 1

    @property
    def config_data(self):
        return self.__config_data
        
    def init_sim(self, reg_file, log_file, nb_file):
        if(nb_file == 1):
            return """#############  INIT SIMULATIONS #############
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
        elif(nb_file != 1 and self.__config_data['multi_res_files'][self.__code] > 1):
            return """
#############  INIT SIMULATIONS #############
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
            return """
#############  INIT SIMULATIONS #############
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
        
    def init_tcl_variables(self, start_window):
        avoid_log_registers = ""
        log_registers = ""
        for reg in self.__config_data['avoid_log_registers']:
            avoid_log_registers += str(reg) + " "
        for reg in self.__config_data['log_registers']:
            log_registers += str(reg) + " "
        return """
###### INIT VARIABLES ######
### CONTROL ###
set periode {periode}
set half_periode [expr {{$periode / 2}}]

set start {start_ns}
set nb_sim 0  ;# Simulation number
set sim_active 1 ;# Active sim Boolean
set cycle_ref {init_cycle} ;# Setting the number of reference cycles for the complete simulation
set cycle_curr 0
set avoid_log_registers_list {{{avoid_log_reg}}}
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
""".format(start_ns=start_window[0], init_cycle=self.__cycle_ref, avoid_log_reg = avoid_log_registers, log_reg = log_registers, periode = self.config_data['cpu_period'])

    def gen_simu_ref(self):
        return """
#############  FIRST SIM #############
###### JUMP TO ATTACK START ######
run "$start ns"
"""

    def run_simu_ref(self):
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

#############  CHECKING SIM VALUES #############
## CHECK ENDING CYCLE ##
set check_cycle [expr [expr $now / 1000 - $start] / 40] ;# Vérification du numéro du cycle actuel
set value_end_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]
set status_end 0
set cycle_curr 0
"""

    def init_sim_attacked(self, nb_sim, start_time, threat, register, size_register = 1):
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

    def init_sim_attacked_multi_bitflip(self, nb_sim, start_time, threat, register_0 = '', size_register_0 = 1, register_1 = '', size_register_1 = 1):
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
set width_register_0 {width_register_0}
set faulted_register_0 {reg_0}
set width_register_1 {width_register_1}
set faulted_register_1 {reg_1}
set bit_flipped_0 -1
set bit_flipped_1 -1

### STATUS END ###
set status_end -1 
""".format(number = nb_sim, start_window = start_time, faute = threat, width_register_0 = size_register_0, reg_0 = register_0, width_register_1 = size_register_1, reg_1 = register_1)

    def init_sim_attacked_single_bitflip_temporel(self, nb_sim, start_time, threat, register_0 = '', size_register_0 = 1, register_1 = '', size_register_1 = 1, t_reg0 = 0, t_reg1 = 0):
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
set width_register_0 {width_register_0}
set faulted_register_0 {reg_0}
set time_fault_register_0 {time_fault_reg_0}
set width_register_1 {width_register_1}
set faulted_register_1 {reg_1}
set time_fault_register_1 {time_fault_reg_1}
set bit_flipped_0 -1
set bit_flipped_1 -1

### STATUS END ###
set status_end -1 
""".format(number = nb_sim, start_window = start_time, faute = threat, width_register_0 = size_register_0, reg_0 = register_0, width_register_1 = size_register_1, reg_1 = register_1, time_fault_reg_0 = t_reg0, time_fault_reg_1 = t_reg1)
    
    def init_sim_attacked_multi_bitflip_reg_multi(self, nb_sim, start_time, threat, register_0 = '', size_register_0 = 1, register_1 = '', size_register_1 = 1):
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
set width_register_0 {width_register_0}
set faulted_register_0 {reg_0}
set width_register_1 {width_register_1}
set faulted_register_1 {reg_1}
set bit_flipped_0 -1
set bit_flipped_1 -1

### STATUS END ###
set status_end -1 
""".format(number = nb_sim, start_window = start_time, faute = threat, width_register_0 = size_register_0, reg_0 = register_0, width_register_1 = size_register_1, reg_1 = register_1)

    def run_sim_attacked(self):
        return """
###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
while {$sim_active == 1} {
    run "$periode ns" ;# run 1 cycle
    incr nb_cycle

    set value_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]

    #############  CHECKING SIM VALUES #############
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

    def run_sim_attacked_simple(self):
        return """
###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
set bool_cycle 0

while {$sim_active == 1} {
    set value_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]

    set error_tcr [examine /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/simple_parity_decoder_tcr/error_o_csr]
    set error_tpr [examine /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/simple_parity_decoder_tpr/error_o_csr]
    set error_addr_tag [examine /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/simple_parity_decoder_addr_rf_tag/error_o_addr_rf_tag]
    set error_26 [examine /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/simple_parity_decoder_26/error_o_26]
    set error_rf_tag [examine /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/simple_parity_decoder_rf_tag/error_o_rf_tag]

    #############  CHECKING SIM VALUES #############
    ## if conditions to stop the run cycles
    if {[expr {$error_tcr} != {"1'h0"}] || [expr {$error_tpr} != {"1'h0"}] || [expr {$error_addr_tag} != {"1'h0"}] || [expr {$error_26} != {"1'h0"}] || [expr {$error_rf_tag} != {"1'h0"}]} {
        ## Detection error ##
        set status_end 5
        set sim_active 0
    } elseif {$nb_cycle > $cycle_ref} {
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

    run "$half_periode ns" ;# run 1/2 cycle
    if {[expr $bool_cycle == 1]} {
        incr nb_cycle
        set bool_cycle 0
    } else {
        set bool_cycle 1
    }
}
"""

    def run_sim_attacked_hamming(self):
        return """
###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
while {$sim_active == 1} {
    run "$periode ns" ;# run 1 cycle
    incr nb_cycle

    set value_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]

    #############  CHECKING SIM VALUES #############
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

    def run_sim_attacked_single_bitflip_temporel(self, fault_injection = ""):
        return """
###### RUN SIM 100 cycles MAX or WHILE PC != 0x84 ######
set bool_cycle 0
while {{$sim_active == 1}} {{
    {fault_injection}
    set value_pc [examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o]
    set error_tcr [examine /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/simple_parity_decoder_tcr/error_o_csr]
    set error_tpr [examine /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/simple_parity_decoder_tpr/error_o_csr]
    set error_addr_tag [examine /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/simple_parity_decoder_addr_rf_tag/error_o_addr_rf_tag]
    set error_26 [examine /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/simple_parity_decoder_26/error_o_26]
    set error_rf_tag [examine /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/simple_parity_decoder_rf_tag/error_o_rf_tag]

    #############  CHECKING SIM VALUES #############
    ## if conditions to stop the run cycles
    if {{[expr {{$error_tcr}} != {{"1'h0"}}] || [expr {{$error_tpr}} != {{"1'h0"}}] || [expr {{$error_addr_tag}} != {{"1'h0"}}] || [expr {{$error_26}} != {{"1'h0"}}] || [expr {{$error_rf_tag}} != {{"1'h0"}}]}} {{
        ## Detection error ##
        set status_end 5
        set sim_active 0
    }} elseif {{$nb_cycle > $cycle_ref}} {{
        ## CYCLE OVERFLOW : CRASH ##
        set sim_active 0
        set status_end 1
    }} elseif {{([expr {{$value_pc}} == {{"32'h0000022c"}}]) && ([expr {{[examine -hex /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/instr_rdata_id_o]}} == {{"32'hfa010113"}}])}} {{
        ## INSN ILL HANDLER ##
        if {{[expr {{$cycle_ill_insn}} == {{[expr $now / 1000]}}]}} {{
            # Illegal insn handler au même moment que simulation 0  : NOTHING #
            set status_end 2
        }} else {{
            # Illegal insn handler à un moment différent que simulation 0 : EXCEPTION DECALEE #
            set status_end 3
        }}
        set sim_active 0
    }} elseif {{($nb_cycle == $cycle_ref) && ([expr {{$value_pc}} == {{$value_end_pc}}])}} {{
        ## RAS ##
        set status_end 0
        set sim_active 0
    }} elseif {{($nb_cycle == $cycle_ref) && ([expr {{$value_pc}} != {{$value_end_pc}}])}} {{
        ## SUCCESS ? ##
        set status_end 4
        set sim_active 0
    }}

    run "$half_periode ns" ;# run 1/2 cycle
    if {{[expr $bool_cycle == 1]}} {{
        incr nb_cycle
        set bool_cycle 0
    }} else {{
        set bool_cycle 1
    }}
}}
""".format(fault_injection = fault_injection)

    def end_sim(self, nbSimCurr, nbSimusTotal):
        if (nbSimCurr != 0) and ((nbSimCurr % self.__config_data['batch_sim'][self.__code]) == 0):
            # print(nbSimCurr, end=' ')
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
        elif nbSimCurr < nbSimusTotal:
            return """
############# END SIM {number} #############
# Restart the simulation
restart
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