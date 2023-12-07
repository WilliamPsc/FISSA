#############  INIT SIMULATIONS #############
set regs_file /home/wpensec/Documents/DRiSCY/pulpino/sw/build/apps/buffer_overflow/CMakeFiles/buffer_overflow.vsimc.dir/buffer_overflow-wop_set0/faulted_regs.yaml
set state_file /home/wpensec/Documents/DRiSCY/pulpino/sw/build/apps/buffer_overflow/CMakeFiles/buffer_overflow.vsimc.dir/buffer_overflow-wop/buffer_overflow-wop.json
set f [open $state_file w]
puts $f "{"
puts $f "\t\"start\": \"[clock format [clock seconds] -format "%Y/%m/%d:%H:%M:%S"]\","
close $f

set f [open $regs_file r]
set reg_file_data [read $f]
close $f

###### INIT VARIABLES ######
### CONTROL ###
set periode 40
set half_periode [expr {$periode / 2}]

set start 137140
set nb_sim 0  ;# Simulation number
set sim_active 1 ;# Active sim Boolean
set cycle_ref 100 ;# Setting the number of reference cycles for the complete simulation
set cycle_curr 0
set log_registers_list {/tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[0] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[1] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[2] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[3] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[4] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[5] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[6] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[7] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[8] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[9] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[10] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[11] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[12] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[13] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[14] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[15] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[16] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[17] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[18] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[19] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[20] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[21] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[22] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[23] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[24] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[25] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[26] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[27] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[28] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[29] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[30] /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg[31] }

### FAULTED REGISTER ###
set threat ""
set width_threat 0
set faulted_register ""

### DETECTED ERRORS ###
set value_end_pc 0
set cycle_ill_insn ""

### STATUS END ###
set status_end -1 ;# End of simulation code (0: reference simulation / 1: reference cycle number exceeded (crash) / 2: jump to illegal instruction handler (identical to reference simulation) / 3: jump to illegal instruction handler (delayed) / 4: success / 5: error detected / ...)

#############  FIRST SIM #############
###### JUMP TO ATTACK START ######
run "$start ns"

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 0 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 1 #############
set nb_sim 1
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 1 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 2 #############
set nb_sim 2
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 2 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 3 #############
set nb_sim 3
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 3 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 4 #############
set nb_sim 4
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 4 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 5 #############
set nb_sim 5
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 5 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 6 #############
set nb_sim 6
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_id_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 6 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 7 #############
set nb_sim 7
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_if_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 7 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 8 #############
set nb_sim 8
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_if_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 8 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 9 #############
set nb_sim 9
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_if_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 9 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 10 #############
set nb_sim 10
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_if_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 10 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 11 #############
set nb_sim 11
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_if_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 11 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 12 #############
set nb_sim 12
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/if_stage_i/pc_if_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 12 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 13 #############
set nb_sim 13
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_a_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 13 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 14 #############
set nb_sim 14
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_a_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 14 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 15 #############
set nb_sim 15
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_a_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 15 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 16 #############
set nb_sim 16
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_a_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 16 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 17 #############
set nb_sim 17
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_a_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 17 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 18 #############
set nb_sim 18
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_a_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 18 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 19 #############
set nb_sim 19
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_b_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 19 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 20 #############
set nb_sim 20
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_b_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 20 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 21 #############
set nb_sim 21
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_b_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 21 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 22 #############
set nb_sim 22
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_b_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 22 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 23 #############
set nb_sim 23
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_b_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 23 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 24 #############
set nb_sim 24
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_b_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 24 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 25 #############
set nb_sim 25
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_c_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 25 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 26 #############
set nb_sim 26
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_c_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 26 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 27 #############
set nb_sim 27
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_c_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 27 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 28 #############
set nb_sim 28
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_c_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 28 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 29 #############
set nb_sim 29
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_c_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 29 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 30 #############
set nb_sim 30
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operand_c_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 30 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 31 #############
set nb_sim 31
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 2
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operator_o_mode
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 31 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 32 #############
set nb_sim 32
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 2
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operator_o_mode
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 32 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 33 #############
set nb_sim 33
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 2
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operator_o_mode
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 33 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 34 #############
set nb_sim 34
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 2
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operator_o_mode
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 34 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 35 #############
set nb_sim 35
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 2
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operator_o_mode
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 35 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 36 #############
set nb_sim 36
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 2
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/alu_operator_o_mode
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 36 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 37 #############
set nb_sim 37
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_d_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 37 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 38 #############
set nb_sim 38
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_d_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 38 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 39 #############
set nb_sim 39
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_d_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 39 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 40 #############
set nb_sim 40
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_d_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 40 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 41 #############
set nb_sim 41
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_d_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 41 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 42 #############
set nb_sim 42
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_d_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 42 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 43 #############
set nb_sim 43
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s1_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 43 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 44 #############
set nb_sim 44
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s1_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 44 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 45 #############
set nb_sim 45
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s1_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 45 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 46 #############
set nb_sim 46
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s1_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 46 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 47 #############
set nb_sim 47
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s1_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 47 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 48 #############
set nb_sim 48
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s1_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 48 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 49 #############
set nb_sim 49
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s2_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 49 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 50 #############
set nb_sim 50
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s2_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 50 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 51 #############
set nb_sim 51
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s2_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 51 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 52 #############
set nb_sim 52
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s2_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 52 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 53 #############
set nb_sim 53
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s2_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 53 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 54 #############
set nb_sim 54
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/check_s2_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 54 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 55 #############
set nb_sim 55
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/is_store_post_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 55 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 56 #############
set nb_sim 56
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/is_store_post_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 56 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 57 #############
set nb_sim 57
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/is_store_post_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 57 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 58 #############
set nb_sim 58
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/is_store_post_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 58 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 59 #############
set nb_sim 59
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/is_store_post_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 59 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 60 #############
set nb_sim 60
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/is_store_post_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 60 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 61 #############
set nb_sim 61
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/memory_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 61 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 62 #############
set nb_sim 62
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/memory_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 62 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 63 #############
set nb_sim 63
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/memory_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 63 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 64 #############
set nb_sim 64
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/memory_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 64 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 65 #############
set nb_sim 65
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/memory_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 65 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 66 #############
set nb_sim 66
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/memory_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 66 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 67 #############
set nb_sim 67
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 5
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/regfile_alu_waddr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 67 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 68 #############
set nb_sim 68
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 5
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/regfile_alu_waddr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 68 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 69 #############
set nb_sim 69
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 5
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/regfile_alu_waddr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 69 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 70 #############
set nb_sim 70
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 5
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/regfile_alu_waddr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 70 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 71 #############
set nb_sim 71
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 5
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/regfile_alu_waddr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 71 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 72 #############
set nb_sim 72
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 5
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/regfile_alu_waddr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 72 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 73 #############
set nb_sim 73
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/register_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 73 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 74 #############
set nb_sim 74
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/register_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 74 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 75 #############
set nb_sim 75
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/register_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 75 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 76 #############
set nb_sim 76
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/register_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 76 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 77 #############
set nb_sim 77
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/register_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 77 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 78 #############
set nb_sim 78
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/register_set_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 78 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 79 #############
set nb_sim 79
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_dest_addr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 79 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 80 #############
set nb_sim 80
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_dest_addr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 80 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 81 #############
set nb_sim 81
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_dest_addr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 81 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 82 #############
set nb_sim 82
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_dest_addr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 82 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 83 #############
set nb_sim 83
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_dest_addr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 83 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 84 #############
set nb_sim 84
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_dest_addr_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 84 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 85 #############
set nb_sim 85
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_source_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 85 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 86 #############
set nb_sim 86
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_source_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 86 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 87 #############
set nb_sim 87
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_source_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 87 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 88 #############
set nb_sim 88
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_source_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 88 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 89 #############
set nb_sim 89
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_source_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 89 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 90 #############
set nb_sim 90
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/store_source_ex_o_tag
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 90 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 91 #############
set nb_sim 91
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/use_store_ops_ex_o
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 91 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 92 #############
set nb_sim 92
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/use_store_ops_ex_o
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 92 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 93 #############
set nb_sim 93
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/use_store_ops_ex_o
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 93 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 94 #############
set nb_sim 94
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/use_store_ops_ex_o
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 94 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 95 #############
set nb_sim 95
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/use_store_ops_ex_o
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 95 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 96 #############
set nb_sim 96
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/use_store_ops_ex_o
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 96 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 97 #############
set nb_sim 97
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[0\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 97 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 98 #############
set nb_sim 98
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[0\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 98 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 99 #############
set nb_sim 99
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[0\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 99 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 100 #############
set nb_sim 100
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[0\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 100 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 101 #############
set nb_sim 101
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[0\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 101 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 102 #############
set nb_sim 102
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[0\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 102 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 103 #############
set nb_sim 103
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[1\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 103 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 104 #############
set nb_sim 104
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[1\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 104 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 105 #############
set nb_sim 105
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[1\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 105 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 106 #############
set nb_sim 106
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[1\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 106 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 107 #############
set nb_sim 107
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[1\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 107 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 108 #############
set nb_sim 108
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[1\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 108 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 109 #############
set nb_sim 109
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[2\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 109 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 110 #############
set nb_sim 110
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[2\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 110 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 111 #############
set nb_sim 111
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[2\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 111 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 112 #############
set nb_sim 112
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[2\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 112 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 113 #############
set nb_sim 113
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[2\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 113 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 114 #############
set nb_sim 114
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[2\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 114 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 115 #############
set nb_sim 115
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[3\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 115 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 116 #############
set nb_sim 116
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[3\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 116 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 117 #############
set nb_sim 117
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[3\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 117 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 118 #############
set nb_sim 118
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[3\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 118 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 119 #############
set nb_sim 119
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[3\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 119 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 120 #############
set nb_sim 120
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[3\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 120 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 121 #############
set nb_sim 121
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[4\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 121 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 122 #############
set nb_sim 122
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[4\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 122 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 123 #############
set nb_sim 123
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[4\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 123 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 124 #############
set nb_sim 124
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[4\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 124 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 125 #############
set nb_sim 125
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[4\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 125 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 126 #############
set nb_sim 126
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[4\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 126 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 127 #############
set nb_sim 127
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[5\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 127 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 128 #############
set nb_sim 128
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[5\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 128 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 129 #############
set nb_sim 129
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[5\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 129 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 130 #############
set nb_sim 130
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[5\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 130 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 131 #############
set nb_sim 131
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[5\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 131 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 132 #############
set nb_sim 132
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[5\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 132 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 133 #############
set nb_sim 133
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[6\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 133 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 134 #############
set nb_sim 134
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[6\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 134 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 135 #############
set nb_sim 135
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[6\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 135 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 136 #############
set nb_sim 136
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[6\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 136 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 137 #############
set nb_sim 137
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[6\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 137 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 138 #############
set nb_sim 138
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[6\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 138 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 139 #############
set nb_sim 139
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[7\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 139 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 140 #############
set nb_sim 140
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[7\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 140 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 141 #############
set nb_sim 141
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[7\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 141 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 142 #############
set nb_sim 142
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[7\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 142 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 143 #############
set nb_sim 143
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[7\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 143 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 144 #############
set nb_sim 144
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[7\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 144 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 145 #############
set nb_sim 145
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[8\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 145 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 146 #############
set nb_sim 146
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[8\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 146 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 147 #############
set nb_sim 147
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[8\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 147 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 148 #############
set nb_sim 148
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[8\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 148 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 149 #############
set nb_sim 149
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[8\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 149 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 150 #############
set nb_sim 150
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[8\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 150 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 151 #############
set nb_sim 151
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[9\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 151 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 152 #############
set nb_sim 152
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[9\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 152 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 153 #############
set nb_sim 153
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[9\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 153 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 154 #############
set nb_sim 154
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[9\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 154 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 155 #############
set nb_sim 155
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[9\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 155 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 156 #############
set nb_sim 156
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[9\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 156 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 157 #############
set nb_sim 157
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[10\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 157 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 158 #############
set nb_sim 158
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[10\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 158 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 159 #############
set nb_sim 159
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[10\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 159 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 160 #############
set nb_sim 160
###### JUMP TO ATTACK START ######
set start_sim "137260 ns"
run "137260 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137260 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[10\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 160 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 161 #############
set nb_sim 161
###### JUMP TO ATTACK START ######
set start_sim "137300 ns"
run "137300 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137300 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[10\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 161 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 162 #############
set nb_sim 162
###### JUMP TO ATTACK START ######
set start_sim "137340 ns"
run "137340 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137340 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[10\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 162 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 163 #############
set nb_sim 163
###### JUMP TO ATTACK START ######
set start_sim "137140 ns"
run "137140 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137140 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[11\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 163 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 164 #############
set nb_sim 164
###### JUMP TO ATTACK START ######
set start_sim "137180 ns"
run "137180 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137180 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[11\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 164 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 165 #############
set nb_sim 165
###### JUMP TO ATTACK START ######
set start_sim "137220 ns"
run "137220 ns" ;# Saut vers la fenêtre d'attaque

set nb_cycle [expr [expr 137220 - $start] / 40]
set sim_active 1
##---------------------
###### FORCE VALUE ON FAULTED REGISTER ######
set threat "set0"
set width_threat 1
set faulted_register /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[11\]
set bit_flipped -1

### STATUS END ###
set status_end -1 

if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    } else {
        set bit_attacked 0
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }
}

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

#############  LOG #############
#---- INIT ----
set f [open $state_file a]
puts $f "\t\"simulation_$nb_sim\": {"

#---- Cycle Checking ----
puts $f "\t\t\"cycle_ref\": $cycle_ref," 
puts $f "\t\t\"cycle_ending\": $check_cycle,"

#---- TCR / TPR ----
puts $f "\t\t\"TPR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tpr_q]\","
puts $f "\t\t\"TCR\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/cs_registers_i/tcr_q]\","

#---- Log Register File ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i/rf_reg\[{$j}\]]\","
}

#---- Log Register File Tag ----
for {set j 0} {$j < 32} {incr j} {
    puts $f "\t\t\"rf_tag$j\": \"[examine -hex /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\]]\","
}

#---- Log Registres du fichiers registres.yaml ----
foreach reg $reg_file_data {
    if {([expr {[lsearch $log_registers_list $reg] == -1}]) && ([expr {$reg != "-"}])} {
        set nom_reg_list [split $reg "/"]
        puts $f "\t\t\"[lindex $nom_reg_list [expr [llength $nom_reg_list] - 1]]\": \"[examine -hex $reg]\","
    }
}

#---- Log faulted register: name, width, threat considered, when ----
if {$nb_sim != 0} {
    puts $f "\t\t\"faulted_register\": \"$faulted_register\","
    puts $f "\t\t\"size_faulted_register\": $width_threat,"
    puts $f "\t\t\"threat\": \"$threat\","
    if {[expr {$threat == "bitflip"}]} {
        puts $f "\t\t\"bit_flipped\": $bit_flipped,"
    }
    puts $f "\t\t\"cycle_attacked\": \"$start_sim\","
}
 
#---- Ending status ----
puts $f "\t\t\"simulation_end_time\": \"[expr {$now / 1000}] ns\","
puts $f "\t\t\"status_end\": $status_end"
puts $f "\t},"

#---- Close log ----
close $f

############# END SIM 165 #############
# Restart the simulation
restart
#------------------------------------