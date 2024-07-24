-- Dissector for link header to determine direction

zdp_link_p2p_proto = Proto("ZDP_Link_P2P", "ZDP point-to-point message data")

in_out = ProtoField.uint8("zdp_link_p2p.zdp_link_p2p", "ZDP Link P2P", base.DEC)

zdp_link_p2p_proto.fields = { in_out }

function zdp_link_p2p_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = zdp_link_p2p_proto.name

    local subtree = tree:add(zdp_link_p2p_proto, buffer(), "ZDP Link Layer Data")
    local direction = buffer(0,1):uint()
    local direction_name = get_direction_name(direction)
    subtree:add(in_out, buffer(0,1)):append_text(" (" .. direction_name .. ")")

end

function get_direction_name(direction)
    local direction_name = "Unknown"

    if direction == 0 then direction_name = "Inbound"
    elseif direction == 1 then direction_name = "Outbound" end

    return direction_name
end