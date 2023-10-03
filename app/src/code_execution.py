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
    def __init__(self, config_data:dict):
        self._config_data = config_data
        self._cycle_ref = self._config_data['cycle_ref']

    @property
    def config_data(self):
        return self._config_data

    def init_sim(self, reg_file, log_file):
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

    def init_tcl_variables(self, start_window):
        return """
###### INIT VARIABLES ######
### CONTROL ###
set periode 40
set start {start_ns}
set nb_sim 0  ;# Simulation number
set sim_active 1 ;# Active sim Boolean
set cycle_ref {init_cycle} ;# Setting the number of reference cycles for the complete simulation
set cycle_curr 0
set log_registers_list [split "{log_reg}" ',']

### FAULTED REGISTER ###
set threat ""
set width_threat 0
set faulted_register ""

### DETECTED ERRORS ###
set value_end_pc 0
set cycle_ill_insn ""

### STATUS END ###
set status_end -1 ;# End of simulation code (0: reference simulation / 1: reference cycle number exceeded (crash) / 2: jump to illegal instruction handler (identical to reference simulation) / 3: jump to illegal instruction handler (delayed) / 4: success / 5: error detected / ...)

""".format(start_ns=start_window[0], init_cycle=self._cycle_ref, log_reg = ','.join(self._config_data['log_registers']))

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

echo $cycle_ill_insn

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
incr nb_sim
############# ATTACK {number} #############
###### JUMP TO ATTACK START ######
set start_sim "{start_window} ns"
run "{start_window} ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr {start_window} - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "{faute}"
set width_threat {width_register}
set faulted_register {reg}
set bit_flipped -1

### STATUS END ###
set status_end -1 
""".format(number = nb_sim, start_window = start_time, faute = threat, width_register = size_register, reg = register)

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

    def end_sim(self, nbSimCurr, nbSimusTotal):
        if nbSimCurr < nbSimusTotal:
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