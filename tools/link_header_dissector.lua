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
    subtree:add(in_out, buffer(0,1)):append_text(" (" .. direction_name[direction] .. ")")
    pinfo.cols.src = location_name[direction]
    pinfo.cols.dst = location_name[math.fmod(direction + 1, 2)]

end

direction_name = 
{
    [0] = "Inbound",
    [1] = "Outbound",
}

location_name = 
{
    [0] = "Remote",
    [1] = "Local",
}