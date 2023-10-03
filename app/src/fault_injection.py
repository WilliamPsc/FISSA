####
## @Author : William PENSEC
## @Version : 0.0
## @Date : 20 janvier 2023
## @Description : 
####

### Import packages ###


### Class ###
class FaultInjection:
    def __init__(self, config_data):
        self._simulator = config_data["name_simulator"]

    def inject_fault(self):
        match self._simulator:
            case "modelsim":
                return self.fault_modelsim()
            case "xsim":
                pass
            case "verilator":
                pass
            case _:
                return ""

    def fault_modelsim(self):
        return """
if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }
    
} elseif {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
} elseif {$threat == "bitflip"} {
    if {$width_threat == 1} {
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {$value^1}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel 40ns
    } else {
        set bit_attacked [expr int(rand()*$width_threat)]
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{$bit_attacked}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{$bit_attacked}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$periode ns"
    }
}
"""

    def set0(self):
        pass

    def set1(self):
        pass

    def bitflip(self):
        pass