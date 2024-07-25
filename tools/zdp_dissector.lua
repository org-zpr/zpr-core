-- Dissector for ZDP Packet

zdp_proto = Proto("zdp", "ZDP Header Dissector")

zpi_val = ProtoField.uint8("zdp.zpi", "ZPI", base.DEC)
zdp_type = ProtoField.uint8("zdp.type", "Type", base.DEC)
excess_len = ProtoField.uint8("zdp.excess_len", "Excess Length", base.DEC)
seq_num = ProtoField.uint16("zdp.seq_num", "Sequence Number", base.DEC)
stream_id = ProtoField.uint64("zdp.streamid", "Stream ID", base.DEC)
pad = ProtoField.bytes("zdp.pad", "Pad")
mac_addr = ProtoField.uint64("zdp.mac", "MAC", base.DEC)
d2d_said = ProtoField.uint8("zdp.d2d_said", "D2D SAID", base.DEC)
agent_packet = ProtoField.bytes("zdp.agent_packet", "Agent Packet")
d2d_mac = ProtoField.uint64("zdp.d2d_mac", "D2D MAC", base.DEC)
management_packet = ProtoField.bytes("zdp.management", "Management Packet")

zdp_proto.fields = { zpi_val, zdp_type, excess_len, seq_num, stream_id, pad, 
                     mac_addr, d2d_said, agent_packet, d2d_mac, management_packet}

function zdp_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = zdp_proto.name

    local subtree = tree:add(zdp_proto, buffer(), "ZDP Header Data")
    subtree:add(zpi_val, buffer(0, 1))

    local type = buffer(2,1):uint()
    local type_name = get_type_name(type)
    subtree:add(zdp_type, buffer(1, 1)):append_text(" (" .. type_name .. ")")

    subtree:add(excess_len, buffer(2, 1))
    subtree:add(seq_num, buffer(3, 2))

    local type = buffer(1,1):uint()
    local real_len = length - buffer(2,1):uint() 

    -- Transit Packet
    if type == 0 then
        subtree:add(stream_id, buffer(5, 4))
        subtree:add(pad, buffer(9, 8))
        subtree:add(mac_addr, buffer(17, 4))
        subtree:add(d2d_said, buffer(21, 1))
        subtree:add(agent_packet, buffer(22, real_len - 26))
        subtree:add(d2d_mac, buffer(real_len - 4, 4))
    -- Stream-oriented Management Message
    elseif type <= 127 then 
        subtree:add(stream_id, buffer(5, 4))
        subtree:add(management_packet, buffer(9, real_len - 21))
        subtree:add(pad, buffer(real_len - 12, 8))
        subtree:add(mac, buffer(real_len - 4, 4))
    -- Other Management Message
    else 
        subtree:add(management_packet, buffer(5, real_len - 17))
        subtree:add(pad, buffer(real_len - 12, 8))
        subtree:add(mac, buffer(real_len - 4, 4))
    end

end

function get_type_name(type)
    local type_name = "Unknown"

    if type == 0 then type_name = "Transit Packet"
    elseif type == 1 then type_name = "Unused" -- not sure if we need to write this here, or if it should remain "Unknown" or something else
    elseif type == 2 then type_name = "Destination Unreachable"
    elseif type == 3 then type_name = "Visa Herald Request"
    elseif type == 4 then type_name = "Visa Herald Response"
    elseif type == 5 then type_name = "Visa Update Request"
    elseif type == 6 then type_name = "Visa Update Response"
    elseif type == 7 then type_name = "Visa Retract Request"
    elseif type == 8 then type_name = "Visa Retract Response"
    elseif type == 9 then type_name = "Visa Deaccept Indication"
    elseif type == 10 then type_name = "Visa Deaccept ACK"
    elseif type == 11 then type_name = "Bind Agent Address Request"
    elseif type == 12 then type_name = "Bind Agent Address Response"
    elseif type == 13 then type_name = "Unbind Agent Address Request"
    elseif type == 14 then type_name = "Unbind Agent Address Response"
    elseif type == 15 then type_name = "Authentication Request"
    elseif type == 16 then type_name = "Set Path MTU"
    elseif type == 17 then type_name = "Authentication Response"
    elseif type >= 18 and type <= 95 then type_name = "Reserved/Unknown" -- This range is not specified in the RFC
    elseif type >= 95 and type <= 126 then type_name = "Reserved for private use and experimentation"
    elseif type == 127 then type_name = "Reserved, Discard"
    elseif type == 128 then type_name = "ZPR ARP"
    elseif type == 129 then type_name = "Key Management"
    elseif type == 130 then type_name = "Discard"
    elseif type == 131 then type_name = "Echo Request"
    elseif type == 132 then type_name = "Echo Response"
    elseif type == 133 then type_name = "Terminate Link or Docking Session Request"
    elseif type == 134 then type_name = "Terminate Link or Docking Session Response"
    elseif type == 135 then type_name = "Terminate Link or Docking Session Indication"
    elseif type == 136 then type_name = "Hello Request"
    elseif type == 137 then type_name = "Hello Response"
    elseif type == 138 then type_name = "Configuration Request"
    elseif type == 139 then type_name = "Configuration Response"
    elseif type == 140 then type_name = "Register Agent Address Request"
    elseif type == 141 then type_name = "Unknown" -- Not specified in RFC
    elseif type == 142 then type_name = "Register Agent Address Response"
    elseif type == 143 then type_name = "Unregister Agent Address Request"
    elseif type == 144 then type_name = "Unregister Agent Address Response"
    elseif type == 145 then type_name = "Report"
    elseif type >= 146 and type <= 223 then type_name = "Reserved/Unknown" -- Not specified in RFC
    elseif type >= 224 and type <= 254 then type_name = "Experimental and Private Use"
    elseif type == 255 then type_name = "Reserved, must not be used" end

    return type_name

end 
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(59274, zdp_proto)