-- Dissector for ZDP Packet

zdp_proto = Proto("zdp", "ZDP Header Dissector")

-- ZDP Headers 
zpi_val = ProtoField.uint8("zdp.zpi", "ZPI", base.DEC)
zdp_type = ProtoField.uint8("zdp.type", "Type", base.DEC)
excess_len = ProtoField.uint8("zdp.excess_len", "Excess Length", base.DEC)
seq_num = ProtoField.uint16("zdp.seq_num", "Sequence Number", base.DEC)
stream_id = ProtoField.uint32("zdp.streamid", "Stream ID", base.DEC)
pad = ProtoField.bytes("zdp.pad", "Pad")
hmac = ProtoField.bytes("zdp.mac", "MAC")
a2a_said = ProtoField.uint8("zdp.a2a_said", "A2A SAID", base.HEX)
agent_packet = ProtoField.bytes("zdp.agent_packet", "Agent Packet")
a2a_mac = ProtoField.uint64("zdp.a2a_mac", "A2A MAC", base.HEX)
management_packet = ProtoField.bytes("zdp.management", "Management Packet")

-- Agent Packet Headers
ip_version = ProtoField.uint8("zdp.ip_version", "IP Version", base.DEC)
ihl = ProtoField.uint8("zdp.ihl", "Internet Header Length", base.DEC)
dscp = ProtoField.uint8("zdp.dscp", "Differentiated Services Code Point", base.DEC)
frag_id = ProtoField.uint16("zdp.frag_id", "Fragment ID", base.DEC)
frag_offset = ProtoField.uint16("zdp.frag_offset", "Fragment Offset", base.DEC)
ttl = ProtoField.uint8("zdp.ttl", "Time to Live", base.DEC)
tc = ProtoField.uint8("zdp.tc", "Traffic Class", base.DEC)
fl = ProtoField.uint32("zdp.fl", "Flow Label", base.DEC)
hop_limit = ProtoField.uint8("zdp.hop_limit", "Hop Limit", base.DEC)
ip_options = ProtoField.bytes("zdp.ip_options", "IP Options")

-- Management Data
trans_id = ProtoField.uint16("zdp.trans_id", "Transaction ID", base.DEC)
adl = ProtoField.uint16("zdp.adl", "Additional Data Length", base.DEC)
reason_code = ProtoField.uint8("zdp.reason_code", "Reason Code", base.DEC)
response_code = ProtoField.uint8("zdp.response_code", "Response Code", base.DEC)
data_length = ProtoField.uint8("zdp.data_length", "Data Length", base.DEC)
additional_data = ProtoField.bytes("zdp.additional", "Optional Additional Data")
req_seq_num = ProtoField.uint16("zdp.req_seq_num", "Request Sequence Number", base.DEC)
ip_protocol_present = ProtoField.uint8("zdp.protocol_present", "IP Protocol Present", base.DEC)
source_port_present = ProtoField.uint8("zdp.source_port_present", "Source Port Information Present", base.DEC)
destination_port_present = ProtoField.uint8("zdp.destination_port_present", "Destination Port Information Present", base.DEC)
source_addr = ProtoField.bytes("zdp.source_addr", "Source IP Address") -- TODO change from bytes to two functions one with type ProtoField.ipv4 and one with ipv6
dest_addr = ProtoField.bytes("zdp.dest_addr", "Destination IP Address")
ip_protocol = ProtoField.uint8("zdp.ip_protocol", "IP Protocol", base.DEC)
source_info = ProtoField.uint16("zdp.source_info", "Source Port Information", base.DEC)
dest_info = ProtoField.uint16("zdp.dest_info", "Destination Port Information", base.DEC)
status_code = ProtoField.uint8("zdp.status_code", "Status Code", base.DEC)
info_len = ProtoField.uint8("zdp.info_len", "Information Length", base.DEC)
status_info = ProtoField.bytes("zdp.status_info", "Optional Additional Status Information")

zdp_proto.fields = { zpi_val, zdp_type, excess_len, seq_num, stream_id, pad, 
                     hmac, a2a_said, agent_packet, a2a_mac, management_packet, ip_version,
                     ihl, dscp, frag_id, frag_offset, ttl, tc, fl, hop_limit, ip_options, trans_id,
                     adl, additional_data, req_seq_num, ip_protocol_present, source_port_present, 
                     destination_port_present, source_addr, dest_addr, ip_protocol, source_info, 
                     dest_info, status_code, info_len, status_info, reason_code, response_code, data_length }

-- Lengths of fields when using Noise Encryption
ZPI = 1
TYPE = 1
EXCESS_LEN = 1
EXCESS_LEN_START = ZPI + TYPE
SEQ_NUM = 2
STREAM_ID = 4
KEY_NOISE_PAD = 0
HMAC = 0
A2A_SAID = 1
A2A_MAC = 8 -- Not sure what the MAC-algorithm-specified-size is (RFC17.2 § 4.2.6.1), but believe zdp.rs 262 specifies
TRANSIT_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + SEQ_NUM + STREAM_ID + KEY_NOISE_PAD + HMAC + A2A_SAID + A2A_MAC
PKT_START = TRANSIT_NON_AGENT_DATA - A2A_MAC
DSCP = 1
FRAG_ID = 2
FRAG_OFFSET = 2
TTL = 1
HOP_LIMIT = 1
PER_FLOW_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + SEQ_NUM + STREAM_ID
NON_FLOW_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + SEQ_NUM
TRANS_ID = 0
ADL = 2
RESPONSE_CODE = 1
REASON_CODE = 1
DL = 1

function zdp_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = zdp_proto.name

    -- TODO shorten main    
    local zdp_header_subtree = tree:add(zdp_proto, buffer(), "ZDP Header Data")

    local zdp_header = Dissector(zdp_header_subtree, buffer)
    zdp_header:add_field(zpi_val, ZPI)

    local type = zdp_header:get_curr_buffer_section(TYPE):uint()
    local type_name = get_type_name(type)
    zdp_header:add_field(zdp_type, TYPE, type_name)
    pinfo.cols.info = type_name

    zdp_header:add_field(excess_len, EXCESS_LEN)
    zdp_header:add_field(seq_num, SEQ_NUM)

    local real_len = length - buffer(EXCESS_LEN_START, EXCESS_LEN):uint() 
    -- Perform different dissections depending on type of packet
    if type == 0 then 
        -- Transit Packet
        zdp_header:add_field(stream_id, STREAM_ID)
        if KEY_NOISE_PAD ~= 0 then  
            zdp_header:add_field(pad, KEY_NOISE_PAD)   
        end
        if HMAC ~= 0 then 
            zdp_header:add_field(hmac, HMAC)
        end
        zdp_header:add_field(a2a_said, A2A_SAID)
        zdp_header:add_field(agent_packet, real_len - TRANSIT_NON_AGENT_DATA)
        zdp_header:set_pos(real_len - A2A_MAC)
        zdp_header:add_field(a2a_mac, A2A_MAC)
        -- zdp_header_subtree:add(compressed_pkt, buffer(curr_pos, 5))

        local agent_header_subtree = tree:add(zdp_proto, buffer(), "Compressed Agent Packet Header Data")
        
        local v4_v6 = get_first_four(buffer(PKT_START, 1):uint())
        agent_header_subtree:add(ip_version, v4_v6)
        local agent_header = Dissector(agent_header_subtree, buffer)
        agent_header:set_pos(PKT_START)

        -- NOTE No updates to this section RE size/position of values, assuming they stayed the same for now
        -- Just want to get this somewhat working first
        if v4_v6 == 4 then
            -- TODO since the curr_pos always has to get incremented, perhaps make a func that both adds to tree and increments curr_pos
            local ihl_val = get_back_four(buffer(PKT_START, 1):uint())
            agent_header_subtree:add(ihl, ihl_val)
            agent_header:increase_pos(1)
            agent_header:add_field(frag_id, FRAG_ID)
            agent_header:add_field(frag_offset, FRAG_OFFSET)
            agent_header:add_field(ttl, TTL)
            -- NOTE Commented this out due to comment below - TCP packet not actually necessarily well formatted
            -- according to TCP standards because of compression
            -- if ihl_val > 5 then
            --     local options_len = ihl_val - ((ihl_val - 5) * 4)
            --     agent_header_subtree:add(ip_options, buffer(17, options_len))
            --     -- pass ip options to an options dissector here (I could not find an existing IP options dissector)
            -- else
            --     -- Should really be passed to a custom compressed TCP packet dissector
            --     -- Perhaps forwarding to the TCP dissector should be commented out for the demo, as it will
            --     -- not show accurate information about the packets. 
            --     Dissector.get("tcp"):call(buffer(17, real_len - IP_NON_AGENT_DATA):tvb(), pinfo, tree)
            -- end

        elseif v4_v6 == 6 then
            local curr_pos = PKT_START
            -- still use hardcoded values here because since the values are bitpacked, if something was changed 
            -- within this section, these lines would need to be changed anyway
            local tc_value = get_middle_eight(buffer(curr_pos, 2):uint())
            agent_header_subtree:add(tc, tc_value)
            curr_pos = curr_pos + 1
            local fl_value = get_back_twelve(buffer(curr_pos, 3):uint())
            agent_header_subtree:add(fl, fl_value)
            curr_pos = curr_pos + 2
            agent_header_subtree:add(hop_limit, buffer(curr_pos, HOP_LIMIT))
            -- Dissector.get("tcp"):call(buffer(15, real_len - IP_NON_AGENT_DATA):tvb(), pinfo, tree)
        end
    elseif type <= 127 then 
        -- Per-Flow Management Message
        zdp_header:add_field(stream_id, STREAM_ID)
        if real_len > PER_FLOW_NON_AGENT_DATA then
            local mgmt_start = zdp_header:get_pos()
            zdp_header:add_field(management_packet, real_len - PER_FLOW_NON_AGENT_DATA)
            decode_management(type, buffer(mgmt_start, real_len - PER_FLOW_NON_AGENT_DATA), tree)
        end
        -- NOTE I believe that both the Pad and the MAC are removed before the packets are captured
    else 
        -- Other Management Message
        if real_len > NON_FLOW_NON_AGENT_DATA then
            local mgmt_start = zdp_header:get_pos()
            zdp_header:add_field(management_packet, real_len - NON_FLOW_NON_AGENT_DATA)
            decode_management(type, buffer(mgmt_start, real_len - NON_FLOW_NON_AGENT_DATA), tree)
        end
    end
end

-- Idiomatic way of doing this may be to actually create a whole new dissector, although that might be challenging
-- becuase we couldn't just forward the managament packet, the type would also have to be forwarded, meaning we would either
-- have to forward basically the whole packet, or create a new tvb with the type and the management packet and forward that
function decode_management(type, buffer, tree)
    local management_subtree = tree:add(zdp_proto, buffer(), "Management Packet Data")
    local management = Dissector(management_subtree, buffer)
    local func = management_table[type]
    if(func) then
        func(management)
    else
        management_subtree:add(management_packet, buffer(0))
    end
end

-- Function definitions must come before table
function handle_echo(management)
    if TRANS_ID > 0 then
        management:add_field(trans_id, TRANS_ID)
    end
    local add_data_len = management:get_curr_buffer_section(ADL):uint()
    management:add_field(adl, ADL)
    if add_data_len > 0 then 
        management:add_field(additional_data, add_data_len)
    end
end

function handle_terminate_ind_req(management)
    if TRANS_ID > 0 then
        management:add_field(trans_id, TRANS_ID)
    end
    management:add_field_with_text_table(reason_code, REASON_CODE, terminate_reason_table)
    local data_len = management:get_curr_buffer_section(DL):uint()
    management:add_field(data_length, DL)
    if data_len > 0 then 
        management:add_field(additional_data, data_len)
    end
end

function handle_terminate_res(management)
    if TRANS_ID > 0 then
        management:add_field(trans_id, TRANS_ID)
    end
    management:add_field_with_text_table(response_code, RESPONSE_CODE, response_code_table)
    local data_len = management:get_curr_buffer_section(DL):uint()
    management:add_field(data_length, DL)
    if data_len > 0 then 
        management:add_field(additional_data, data_len)
    end
end

function handle_hello_req(management)
end

function handle_hello_res(management)
    management:add_field_with_text_table(response_code, RESPONSE_CODE, response_code_table)
    -- TODO handle TLVs
end

-- "Class" that contains the tree, buffer, and current position
function Dissector(init_tree, init_buffer) 
    local dissector = { tree = init_tree, buffer = init_buffer, pos = 0 }

    local methods = {
        add_field = function(self, field, len)
            self.tree:add(field, self.buffer(self.pos, len))
            self.pos = self.pos + len
        end,
        add_field_with_text_table = function(self, field, len, table)
            local key = self.buffer(self.pos, len):uint()
            self.tree:add(field, self.buffer(self.pos, len)):append_text(" (" .. table[key] .. ")")
            self.pos = self.pos + len
        end,
        add_field_with_text = function(self, field, len, text)
            self.tree:add(field, self.buffer(self.pos, len)):append_text(" (" .. text .. ")")
            self.pos = self.pos + len
        end,
        set_pos = function(self, val)
            self.pos = val
        end,
        increase_pos = function(self, val)
            self.pos = self.pos + val
        end,
        get_pos = function(self)
            return self.pos
        end,
        get_curr_buffer_section = function(self, len)
            return self.buffer(self.pos, len)
        end,
        get_buffer_section = function(self, start, len)
            return self.buffer(start, len)
        end
    }

    setmetatable(dissector, {__index = methods })
    return dissector
end

-- function handle_bind_agent_addr_request(buffer, management_subtree)
--     local version = buffer(0, 1):uint()
--     management_subtree:add(ip_version, buffer(0, 1))
--     local ip_proto_present = get_first_bit(buffer(1, 1):uint())
--     management_subtree:add(ip_protocol_present, ip_proto_present):append_text(" (" .. presence_value[ip_proto_present] .. ")")
--     local source_present = get_second_bit(buffer(1, 1):uint())
--     management_subtree:add(source_port_present, source_present):append_text(" (" .. presence_value[source_present] .. ")")
--     local dest_present = get_third_bit(buffer(1, 1):uint())
--     management_subtree:add(destination_port_present, dest_present):append_text(" (" .. presence_value[dest_present] .. ")")
    
--     local addr_len = 4
--     if version == 6 then addr_len = 16 end

--     management_subtree:add(source_addr, buffer(2, addr_len))
--     management_subtree:add(dest_addr, buffer(2 + addr_len, addr_len))

--     local bytes_used = 2 + (2 * addr_len)
--     if ip_proto_present == 1 then 
--         management_subtree:add(ip_protocol, buffer(bytes_used, 1))
--         bytes_used = bytes_used + 1
--     end
     
--     if source_present == 1 then 
--         management_subtree:add(source_info, buffer(bytes_used, 2))
--         bytes_used = bytes_used + 2
--     end

--     if dest_present == 1 then 
--         management_subtree:add(dest_info, buffer(bytes_used, 2))
--     end
-- end

-- function handle_bind_agent_addr_response(buffer, management_subtree)
--     management_subtree:add(req_seq_num, buffer(0, 2))
--     management_subtree:add(status_code, buffer(2, 1))
--     management_subtree:add(info_len, buffer(3, 1))
--     local add_info_len = buffer(3, 1):uint()
--     if add_info_len > 1 then
--         management_subtree:add(status_info, buffer(4, add_info_len)) 
--     end                                                          
-- end

-- TODO
-- more management handler functions
-- cleanup existing code
-- functions for commonly dont actions (ie adding to tree and incrementing value)



management_table = 
{
    [11] = handle_bind_agent_addr_request,
    [12] = handle_bind_agent_addr_response,
    [131] = handle_echo,
    [132] = handle_echo,
    [133] = handle_terminate_ind_req,
    [134] = handle_terminate_res,
    [135] = handle_terminate_ind_req,
    [136] = handle_hello_req,
    [137] = handle_hello_res,
}

presence_value = 
{
    [0] = "Not Present",
    [1] = "Present",
}

-- Gets type name for a packet using the table below. Will return nil if type is 
-- not between 0 and 254
function get_type_name(type)
    local type_name = type_name_table[type]

    if type_name ~= nil then return type_name
    elseif type >= 18 and type <= 95 then type_name = "Reserved/Unknown" -- This range is not specified in the RFC
    elseif type >= 95 and type <= 126 then type_name = "Reserved for private use and experimentation"
    elseif type >= 146 and type <= 223 then type_name = "Reserved/Unknown" -- Not specified in RFC
    elseif type >= 224 and type <= 254 then type_name = "Experimental and Private Use" end

    return type_name
end 

type_name_table =
{
    [0] = "Transit Packet",
    [1] = "Unused",
    [2] = "Destination Unreachable",
    [3] = "Visa Herald Request",
    [4] = "Visa Herald Response",
    [5] = "Unused",
    [6] = "Unused",
    [7] = "Visa Retract Request",
    [8] = "Visa Retract Response",
    [9] = "Stream ID Withdrawl Request",
    [10] = "Stream ID Withdrawl Response",
    [11] = "Bind Endpoint Address Request",
    [12] = "Bind Endpoint Address Response",
    [13] = "Unbind Endpoint Address Request",
    [14] = "Unbind Endpoint Address Response",
    [15] = "Authentication Request",
    [16] = "Authentication Response",
    [17] = "Set Path MTU Request",
    [18] = "Set Path MTU Response",
    [127] = "Reserved, Discard",
    [128] = "ZPR ARP",
    [129] = "Key Management",
    [130] = "Discard",
    [131] = "Echo Request",
    [132] = "Echo Response",
    [133] = "Terminate Link or Docking Session Request",
    [134] = "Terminate Link or Docking Session Response",
    [135] = "Terminate Link or Docking Session Indication",
    [136] = "Hello Request",
    [137] = "Hello Response",
    [138] = "Configuration Request",
    [139] = "Configuration Response",
    [140] = "Acquire ZPR Address Request",
    [141] = "Unused",
    [142] = "Acquire ZPR Address Response",
    [143] = "Unused",
    [144] = "Unused",
    [145] = "Report",
    [146] = "Init Authentication Request",
    [147] = "Init Authentication Response",
    [148] = "Grant ZPR Address Request",
    [149] = "Grant ZPR Address Response",
    [255] = "Reserved, must not be used",
}

terminate_reason_table =
{
    [0] = "Other",
    [1] = "Unused1",
    [2] = "Request Timed Out",
    [3] = "Reset",
    [4] = "Shutdown",
}

response_code_table = 
{
    [0] = "Success",
    [1] = "Other",
}

-- Bit un-packing funcs
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

function get_first_bit(one_byte)
    return bit.rshift(one_byte, 7)
end

function get_second_bit(one_byte)
    local masked = bit.band(one_byte, 0x40)
    return bit.rshift(masked, 6)
end

function get_third_bit(one_byte)
    local masked = bit.band(one_byte, 0x20)
    return bit.rshift(masked, 5)
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(1021, zdp_proto)

local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(253, zdp_proto)

local eth_type = DissectorTable.get("ethertype")
eth_type:add(0x88B5, zdp_proto)