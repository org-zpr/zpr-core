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
ip_version = ProtoField.uint8("zdp.ip_version", "IP Version", base.DEC)
ihl = ProtoField.uint8("zdp.ihl", "Internet Header Length", base.DEC)
dscp = ProtoField.uint8("zdp.dscp", "Differentiated Services Code Point", base.DEC)
frag_id = ProtoField.uint16("zdp.frag_id", "Fragment ID", base.DEC)
frag_offset = ProtoField.uint16("zdp.frag_offset", "Fragment Offset", base.DEC)
ttl = ProtoField.uint8("zdp.ttl", "Time to Live", base.DEC)
tc = ProtoField.uint8("zdp.tc", "Traffic Class", base.DEC)
fl = ProtoField.uint32("zdp.fl", "Flow Label", base.DEC)
hop_limit = ProtoField.uint8("zdp.hop_limit", "Hop Limit", base.DEC)

zdp_proto.fields = { zpi_val, zdp_type, excess_len, seq_num, stream_id, pad, 
                     mac_addr, d2d_said, agent_packet, d2d_mac, management_packet, ip_version,
                     ihl, dscp, frag_id, frag_offset, ttl, tc, fl, hop_limit }

function zdp_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = zdp_proto.name

    -- TODO look into adding to a subtree from a funciton, this "main" function 
    -- is rather long, and is doing many things
    local zdp_header_subtree = tree:add(zdp_proto, buffer(), "ZDP Header Data") -- It's really dissecting all fields of the ZDP packet, not just the header, right?
    zdp_header_subtree:add(zpi_val, buffer(0, 1))
    zdp_header_subtree:add(zdp_type, buffer(1, 1))
    zdp_header_subtree:add(excess_len, buffer(2, 1))
    zdp_header_subtree:add(seq_num, buffer(3, 2))

    local type = buffer(1,1):uint()
    local real_len = length - buffer(2,1):uint() 

    -- Perform different dissections depending on type of packet
    if type == 0 then 
        -- Transit Packet
        zdp_header_subtree:add(stream_id, buffer(5, 4))
        zdp_header_subtree:add(pad, buffer(9, 8))
        zdp_header_subtree:add(mac_addr, buffer(17, 4))
        zdp_header_subtree:add(d2d_said, buffer(21, 1))
        zdp_header_subtree:add(agent_packet, buffer(22, real_len - 26))
        zdp_header_subtree:add(d2d_mac, buffer(real_len - 4, 4))

        local agent_header_subtree = tree:add(zdp_proto, buffer(), "Compressed Agent Packet Header Data")
        local v4_v6 = get_first_four(buffer(22, 1):uint())
        agent_header_subtree:add(ip_version, v4_v6)
        if v4_v6 == 4 then
            local ihl_val = get_back_four(buffer(22, 1):uint())
            agent_header_subtree:add(ihl, ihl_val)
            agent_header_subtree:add(dscp, buffer(23, 1))
            agent_header_subtree:add(frag_id, buffer(24, 2))
            agent_header_subtree:add(frag_offset, buffer(26, 2))
            agent_header_subtree:add(ttl, buffer(27, 1))
        elseif v4_v6 == 6 then
            local tc_value = get_middle_eight(buffer(22, 2):uint())
            agent_header_subtree:add(tc, tc_value)
            local fl_value = get_back_twelve(buffer(23, 3):uint())
            agent_header_subtree:add(fl, fl_value)
            agent_header_subtree:add(hop_limit, buffer(26, 1))
        end
    elseif type <= 127 then 
        -- Stream-oriented Management Message
        zdp_header_subtree:add(stream_id, buffer(5, 4))
        zdp_header_subtree:add(management_packet, buffer(9, real_len - 21))
        zdp_header_subtree:add(pad, buffer(real_len - 12, 8))
        zdp_header_subtree:add(mac, buffer(real_len - 4, 4))
    else 
        -- Other Management Message
        zdp_header_subtree:add(management_packet, buffer(5, real_len - 17))
        zdp_header_subtree:add(pad, buffer(real_len - 12, 8))
        zdp_header_subtree:add(mac, buffer(real_len - 4, 4))
    end


    
end

function get_first_four(one_byte) 
    return bit.rshift(one_byte, 4)
end

function get_back_four(one_byte)
    return bit.band(one_byte, 0x0F)
end

function get_middle_eight(two_bytes)
    local masked = bit.band(two_bytes, 0x0FF0)
    return bit.rshift(masked, 4)
end

function get_back_twelve(three_bytes) 
    return bit.band(three_bytes, 0x0FFFFF)
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(1201, zdp_proto)

local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(253, zdp_proto)

local eth_type = DissectorTable.get("ethertype")
eth_type:add(0x88B5, zdp_proto)