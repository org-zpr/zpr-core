-- Dissector for ZDP Packet

zdp_proto = Proto("zdp", "ZDP Header Dissector")

zpi_val = ProtoField.uint8("zdp.zpi", "ZPI", base.DEC)
zdp_type = ProtoField.uint8("zdp.type", "Type", base.DEC)
excess_len = ProtoField.uint8("zdp.excess_len", "Excess Length", base.DEC)
seq_num = ProtoField.uint16("zdp.seq_num", "Sequence Number", base.DEC)
stream_id = ProtoField.uint32("zdp.streamid", "Stream ID", base.DEC)
pad = ProtoField.bytes("zdp.pad", "Pad")
mac_addr = ProtoField.uint32("zdp.mac", "MAC", base.DEC)
d2d_said = ProtoField.uint8("zdp.d2d_said", "D2D SAID", base.DEC)
agent_packet = ProtoField.bytes("zdp.agent_packet", "Agent Packet")
d2d_mac = ProtoField.uint32("zdp.d2d_mac", "D2D MAC", base.DEC)
management_packet = ProtoField.bytes("zdp.management", "Management Packet")

zdp_proto.fields = { zpi_val, zdp_type, excess_len, seq_num, stream_id, pad, 
                     mac_addr, d2d_said, agent_packet, d2d_mac, management_packet}

function zdp_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = zdp_proto.name

    local subtree = tree:add(zdp_proto, buffer(), "ZDP Header Data")
    subtree:add(zpi_val, buffer(0, 1))
    subtree:add(zdp_type, buffer(1, 1))
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

local udp_port = DissectorTable.get("udp.port")
udp_port:add(1021, zdp_proto)

local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(253, zdp_proto)

local eth_type = DissectorTable.get("ethertype")
eth_type:add(0x88B5, zdp_proto)