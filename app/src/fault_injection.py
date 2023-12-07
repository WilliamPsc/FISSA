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

    def inject_fault(self, bit_flipped = 0):
        match self._simulator:
            case "modelsim":
                return self.fault_modelsim(bit_flipped)
            case "xsim":
                pass
            case "verilator":
                pass
            case _:
                return ""

    def fault_modelsim(self, bit_flipped):
        return """
if {{$threat == "set0"}} {{
    if {{$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"}} {{
        for {{set j 0}} {{$j < [llength $faulted_register]}} {{incr j}} {{
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{{$j}}\] "1'h0" 0 -cancel "$periode ns"
        }}
    }} else {{
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }}  
}} elseif {{$threat == "set1"}} {{
    if {{$width_threat == 1}} {{
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    }} else {{
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }}
}} elseif {{$threat == "bitflip"}} {{
    if {{$width_threat == 1}} {{
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {{$value^1}}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    }} else {{
        set bit_attacked {wreg}
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{{$bit_attacked}}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{{$bit_attacked}}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }}
}}
""".format(wreg = bit_flipped)

    def set0(self):
        return """
if {$threat == "set0"} {
    if {$faulted_register == "/tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg"} {
        for {set j 0} {$j < [llength $faulted_register]} {incr j} {
            force -freeze /tb/top_i/core_region_i/RISCV_CORE/id_stage_i/registers_i_tag/rf_reg\[{$j}\] "1'h0" 0 -cancel "$periode ns"
        }
    } else {
        force -freeze $faulted_register 0 0 -cancel "$periode ns"
    }  
}
"""

    def set1(self):
        return """
if {$threat == "set1"} {
    if {$width_threat == 1} {
        force -freeze $faulted_register 1'h1 0 -cancel "$periode ns"
    } else {
        force -freeze $faulted_register [concat [expr $width_threat]'h[string repeat F $width_threat]] 0 -cancel "$periode ns"
    }
}
"""

    def bitflip(self, bit_flipped):
        return """
if {{$threat == "bitflip"}} {{
    if {{$width_threat == 1}} {{
        set value_curr_reg [examine -bin $faulted_register]
        set value [lindex [split $value_curr_reg b] 1]
        set bf [expr {{$value^1}}]
        set bit_flipped 0
        force -freeze $faulted_register $bf 0 -cancel "$half_periode ns"
    }} else {{
        set bit_attacked {wreg}
        set bit_flipped $bit_attacked
        set value_curr_reg [examine -hex $faulted_register\[{{$bit_attacked}}\]]
        set value [lindex [split $value_curr_reg h] 1]
        set bitflip_faulted_register [expr $value^1]
        force -freeze $faulted_register\[{{$bit_attacked}}\] [concat $width_threat'h$bitflip_faulted_register] 0 -cancel "$half_periode ns"
    }}
}}
""".format(wreg = bit_flipped)
    
    def multi_bitflip_spatial(self, bit_flipped_1, bit_flipped_2):
        """Generate code for a spatial multi-bit-flip fault threat model"""
        pass

    def multi_bitflip_temporel(self):
        """Generate code for a multi-bit-flip temporal fault threat model"""
        pass