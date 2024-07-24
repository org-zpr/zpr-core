-- Dissector for link header to determine direction

zdp_link_p2p_proto = Proto("Direction", "Inbound/Outbound Dissector")

in_out = ProtoField.uint8("direction.direction", "Direction", base.DEC)

zdp_link_p2p_proto.fields = { in_out }

function zdp_link_p2p_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = zdp_link_p2p_proto.name

    local subtree = tree:add(zdp_link_p2p_proto, buffer(), "Direction Data")
    local direction = buffer(0,1):uint()
    local direction_name = get_direction_name(direction)
    subtree:add(in_out, buffer(0,1)):append_text(" (" .. direction_name .. ")")

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(59274, zdp_link_p2p_proto)

function get_direction_name(direction)
    local direction_name = "Unknown"

    if direction == 0 then direction_name = "Inbound"
    elseif direction == 1 then direction_name = "Outbound" end

    return direction_name
end