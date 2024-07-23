-- Dissector for link header to determine direction

zdp_link_p2p_proto = Proto("Direction", "Inbound/Outbound Dissector")

-- direction = ProtoField.u8()

function zdp_link_p2p_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = zdp_link_p2p_proto.name

    local subtree = tree:add(zdp_link_p2p_proto, buffer(), "Direction Data")
    subtree:add(buffer(0,1), "Direction: " .. buffer(0,1):uint())

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(59274, zdp_link_p2p_proto)