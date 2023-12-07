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
############# ATTACK 166 #############
set nb_sim 166
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

############# END SIM 166 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 167 #############
set nb_sim 167
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

############# END SIM 167 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 168 #############
set nb_sim 168
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

############# END SIM 168 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 169 #############
set nb_sim 169
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

############# END SIM 169 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 170 #############
set nb_sim 170
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

############# END SIM 170 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 171 #############
set nb_sim 171
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

############# END SIM 171 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 172 #############
set nb_sim 172
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

############# END SIM 172 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 173 #############
set nb_sim 173
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

############# END SIM 173 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 174 #############
set nb_sim 174
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

############# END SIM 174 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 175 #############
set nb_sim 175
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

############# END SIM 175 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 176 #############
set nb_sim 176
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

############# END SIM 176 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 177 #############
set nb_sim 177
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

############# END SIM 177 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 178 #############
set nb_sim 178
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

############# END SIM 178 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 179 #############
set nb_sim 179
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

############# END SIM 179 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 180 #############
set nb_sim 180
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

############# END SIM 180 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 181 #############
set nb_sim 181
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

############# END SIM 181 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 182 #############
set nb_sim 182
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

############# END SIM 182 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 183 #############
set nb_sim 183
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

############# END SIM 183 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 184 #############
set nb_sim 184
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

############# END SIM 184 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 185 #############
set nb_sim 185
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

############# END SIM 185 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 186 #############
set nb_sim 186
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

############# END SIM 186 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 187 #############
set nb_sim 187
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

############# END SIM 187 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 188 #############
set nb_sim 188
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

############# END SIM 188 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 189 #############
set nb_sim 189
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

############# END SIM 189 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 190 #############
set nb_sim 190
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

############# END SIM 190 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 191 #############
set nb_sim 191
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

############# END SIM 191 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 192 #############
set nb_sim 192
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

############# END SIM 192 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 193 #############
set nb_sim 193
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

############# END SIM 193 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 194 #############
set nb_sim 194
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

############# END SIM 194 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 195 #############
set nb_sim 195
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

############# END SIM 195 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 196 #############
set nb_sim 196
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

############# END SIM 196 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 197 #############
set nb_sim 197
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

############# END SIM 197 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 198 #############
set nb_sim 198
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

############# END SIM 198 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 199 #############
set nb_sim 199
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

############# END SIM 199 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 200 #############
set nb_sim 200
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

############# END SIM 200 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 201 #############
set nb_sim 201
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

############# END SIM 201 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 202 #############
set nb_sim 202
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

############# END SIM 202 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 203 #############
set nb_sim 203
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

############# END SIM 203 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 204 #############
set nb_sim 204
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

############# END SIM 204 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 205 #############
set nb_sim 205
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

############# END SIM 205 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 206 #############
set nb_sim 206
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

############# END SIM 206 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 207 #############
set nb_sim 207
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

############# END SIM 207 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 208 #############
set nb_sim 208
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

############# END SIM 208 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 209 #############
set nb_sim 209
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

############# END SIM 209 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 210 #############
set nb_sim 210
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

############# END SIM 210 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 211 #############
set nb_sim 211
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

############# END SIM 211 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 212 #############
set nb_sim 212
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

############# END SIM 212 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 213 #############
set nb_sim 213
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

############# END SIM 213 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 214 #############
set nb_sim 214
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

############# END SIM 214 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 215 #############
set nb_sim 215
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

############# END SIM 215 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 216 #############
set nb_sim 216
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

############# END SIM 216 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 217 #############
set nb_sim 217
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

############# END SIM 217 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 218 #############
set nb_sim 218
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

############# END SIM 218 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 219 #############
set nb_sim 219
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

############# END SIM 219 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 220 #############
set nb_sim 220
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

############# END SIM 220 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 221 #############
set nb_sim 221
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

############# END SIM 221 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 222 #############
set nb_sim 222
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

############# END SIM 222 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 223 #############
set nb_sim 223
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

############# END SIM 223 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 224 #############
set nb_sim 224
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

############# END SIM 224 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 225 #############
set nb_sim 225
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

############# END SIM 225 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 226 #############
set nb_sim 226
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

############# END SIM 226 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 227 #############
set nb_sim 227
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

############# END SIM 227 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 228 #############
set nb_sim 228
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

############# END SIM 228 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 229 #############
set nb_sim 229
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

############# END SIM 229 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 230 #############
set nb_sim 230
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

############# END SIM 230 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 231 #############
set nb_sim 231
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

############# END SIM 231 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 232 #############
set nb_sim 232
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

############# END SIM 232 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 233 #############
set nb_sim 233
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

############# END SIM 233 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 234 #############
set nb_sim 234
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

############# END SIM 234 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 235 #############
set nb_sim 235
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

############# END SIM 235 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 236 #############
set nb_sim 236
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

############# END SIM 236 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 237 #############
set nb_sim 237
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

############# END SIM 237 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 238 #############
set nb_sim 238
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

############# END SIM 238 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 239 #############
set nb_sim 239
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

############# END SIM 239 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 240 #############
set nb_sim 240
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

############# END SIM 240 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 241 #############
set nb_sim 241
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

############# END SIM 241 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 242 #############
set nb_sim 242
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

############# END SIM 242 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 243 #############
set nb_sim 243
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

############# END SIM 243 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 244 #############
set nb_sim 244
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

############# END SIM 244 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 245 #############
set nb_sim 245
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

############# END SIM 245 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 246 #############
set nb_sim 246
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

############# END SIM 246 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 247 #############
set nb_sim 247
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

############# END SIM 247 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 248 #############
set nb_sim 248
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

############# END SIM 248 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 249 #############
set nb_sim 249
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

############# END SIM 249 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 250 #############
set nb_sim 250
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

############# END SIM 250 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 251 #############
set nb_sim 251
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

############# END SIM 251 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 252 #############
set nb_sim 252
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

############# END SIM 252 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 253 #############
set nb_sim 253
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

############# END SIM 253 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 254 #############
set nb_sim 254
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

############# END SIM 254 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 255 #############
set nb_sim 255
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

############# END SIM 255 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 256 #############
set nb_sim 256
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

############# END SIM 256 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 257 #############
set nb_sim 257
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

############# END SIM 257 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 258 #############
set nb_sim 258
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

############# END SIM 258 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 259 #############
set nb_sim 259
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

############# END SIM 259 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 260 #############
set nb_sim 260
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

############# END SIM 260 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 261 #############
set nb_sim 261
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

############# END SIM 261 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 262 #############
set nb_sim 262
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

############# END SIM 262 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 263 #############
set nb_sim 263
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

############# END SIM 263 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 264 #############
set nb_sim 264
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

############# END SIM 264 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 265 #############
set nb_sim 265
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

############# END SIM 265 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 266 #############
set nb_sim 266
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

############# END SIM 266 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 267 #############
set nb_sim 267
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

############# END SIM 267 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 268 #############
set nb_sim 268
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

############# END SIM 268 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 269 #############
set nb_sim 269
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

############# END SIM 269 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 270 #############
set nb_sim 270
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

############# END SIM 270 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 271 #############
set nb_sim 271
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

############# END SIM 271 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 272 #############
set nb_sim 272
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

############# END SIM 272 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 273 #############
set nb_sim 273
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

############# END SIM 273 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 274 #############
set nb_sim 274
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

############# END SIM 274 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 275 #############
set nb_sim 275
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

############# END SIM 275 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 276 #############
set nb_sim 276
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

############# END SIM 276 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 277 #############
set nb_sim 277
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

############# END SIM 277 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 278 #############
set nb_sim 278
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

############# END SIM 278 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 279 #############
set nb_sim 279
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

############# END SIM 279 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 280 #############
set nb_sim 280
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

############# END SIM 280 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 281 #############
set nb_sim 281
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

############# END SIM 281 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 282 #############
set nb_sim 282
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

############# END SIM 282 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 283 #############
set nb_sim 283
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

############# END SIM 283 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 284 #############
set nb_sim 284
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

############# END SIM 284 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 285 #############
set nb_sim 285
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

############# END SIM 285 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 286 #############
set nb_sim 286
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

############# END SIM 286 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 287 #############
set nb_sim 287
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

############# END SIM 287 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 288 #############
set nb_sim 288
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

############# END SIM 288 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 289 #############
set nb_sim 289
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

############# END SIM 289 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 290 #############
set nb_sim 290
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

############# END SIM 290 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 291 #############
set nb_sim 291
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

############# END SIM 291 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 292 #############
set nb_sim 292
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

############# END SIM 292 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 293 #############
set nb_sim 293
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

############# END SIM 293 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 294 #############
set nb_sim 294
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

############# END SIM 294 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 295 #############
set nb_sim 295
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

############# END SIM 295 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 296 #############
set nb_sim 296
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

############# END SIM 296 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 297 #############
set nb_sim 297
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

############# END SIM 297 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 298 #############
set nb_sim 298
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

############# END SIM 298 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 299 #############
set nb_sim 299
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

############# END SIM 299 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 300 #############
set nb_sim 300
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

############# END SIM 300 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 301 #############
set nb_sim 301
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

############# END SIM 301 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 302 #############
set nb_sim 302
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

############# END SIM 302 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 303 #############
set nb_sim 303
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

############# END SIM 303 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 304 #############
set nb_sim 304
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

############# END SIM 304 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 305 #############
set nb_sim 305
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

############# END SIM 305 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 306 #############
set nb_sim 306
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

############# END SIM 306 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 307 #############
set nb_sim 307
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

############# END SIM 307 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 308 #############
set nb_sim 308
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

############# END SIM 308 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 309 #############
set nb_sim 309
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

############# END SIM 309 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 310 #############
set nb_sim 310
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

############# END SIM 310 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 311 #############
set nb_sim 311
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

############# END SIM 311 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 312 #############
set nb_sim 312
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

############# END SIM 312 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 313 #############
set nb_sim 313
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

############# END SIM 313 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 314 #############
set nb_sim 314
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

############# END SIM 314 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 315 #############
set nb_sim 315
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

############# END SIM 315 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 316 #############
set nb_sim 316
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

############# END SIM 316 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 317 #############
set nb_sim 317
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

############# END SIM 317 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 318 #############
set nb_sim 318
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

############# END SIM 318 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 319 #############
set nb_sim 319
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

############# END SIM 319 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 320 #############
set nb_sim 320
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

############# END SIM 320 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 321 #############
set nb_sim 321
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

############# END SIM 321 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 322 #############
set nb_sim 322
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

############# END SIM 322 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 323 #############
set nb_sim 323
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

############# END SIM 323 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 324 #############
set nb_sim 324
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

############# END SIM 324 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 325 #############
set nb_sim 325
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

############# END SIM 325 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 326 #############
set nb_sim 326
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

############# END SIM 326 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 327 #############
set nb_sim 327
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

############# END SIM 327 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 328 #############
set nb_sim 328
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

############# END SIM 328 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 329 #############
set nb_sim 329
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

############# END SIM 329 #############
# Restart the simulation
restart
#------------------------------------
##############################################################################
############# ATTACK 330 #############
set nb_sim 330
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

############# END SIM 330 #############
# Write date of end
set f [open $state_file a]
puts $f "\"end\": \"[clock format [clock seconds] -format "%Y/%m/%d:%H:%M:%S"]\""
puts $f "}"
close $f

# Exit the simulation
exit
#------------------------------------