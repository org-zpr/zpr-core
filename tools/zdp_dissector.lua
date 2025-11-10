-- Dissector for ZDP Packet

zdp_proto = Proto("zdp", "ZDP Header Dissector")

-- ZDP Headers 
zpi_val = ProtoField.uint8("zdp.zpi", "ZPI", base.DEC)
zdp_type = ProtoField.uint8("zdp.type", "Type", base.DEC)
excess_len = ProtoField.uint8("zdp.excess_len", "Excess Length", base.DEC)
seq_num = ProtoField.uint64("zdp.seq_num", "Sequence Number", base.DEC)
stream_id = ProtoField.uint32("zdp.streamid", "Stream ID", base.DEC)
pad = ProtoField.bytes("zdp.pad", "Pad")
hmac = ProtoField.bytes("zdp.mac", "HMAC")
a2a_said = ProtoField.uint8("zdp.a2a_said", "A2A SAID", base.HEX)
agent_packet = ProtoField.bytes("zdp.agent_packet", "Agent Packet")
a2a_mac = ProtoField.uint64("zdp.a2a_mac", "A2A MAC", base.HEX)
management_packet = ProtoField.bytes("zdp.management", "Management Packet")

-- Agent Packet Headers
ip_version = ProtoField.uint8("zdp.ip_version", "IP Version", base.DEC)
ihl = ProtoField.uint8("zdp.ihl", "Internet Header Length", base.DEC)
frag_id = ProtoField.uint16("zdp.frag_id", "Fragment ID", base.DEC)
frag_offset = ProtoField.uint16("zdp.frag_offset", "Fragment Offset", base.DEC)
ttl = ProtoField.uint8("zdp.ttl", "Time to Live", base.DEC)
tc = ProtoField.uint8("zdp.tc", "Traffic Class", base.DEC)
fl = ProtoField.uint32("zdp.fl", "Flow Label", base.DEC)
hop_limit = ProtoField.uint8("zdp.hop_limit", "Hop Limit", base.DEC)
-- dscp = ProtoField.uint8("zdp.dscp", "Differentiated Services Code Point", base.DEC)
-- ip_options = ProtoField.bytes("zdp.ip_options", "IP Options")

-- Management Data
trans_id = ProtoField.uint16("zdp.trans_id", "Transaction ID", base.DEC)
adl = ProtoField.uint16("zdp.adl", "Additional Data Length", base.DEC)
reason_code = ProtoField.uint8("zdp.reason_code", "Reason Code", base.DEC)
response_code = ProtoField.uint8("zdp.response_code", "Response Code", base.DEC)
data_length_u8 = ProtoField.uint8("zdp.data_len_t", "Data Length", base.DEC)
data_length_u16 = ProtoField.uint16("zdp.data_len_i", "Data Length", base.DEC)
additional_data = ProtoField.bytes("zdp.additional", "Optional Additional Data")
source_port_present = ProtoField.uint8("zdp.source_port_present", "Source Port Information Present", base.DEC)
dest_port_present = ProtoField.uint8("zdp.dest_port_present", "Destination Port Information Present", base.DEC)
source_addr_v4 = ProtoField.ipv4("zdp.source_addr_v4", "Source IP Address")
dest_addr_v4 = ProtoField.ipv4("zdp.dest_addr_v4", "Destination IP Address")
source_addr_v6 = ProtoField.ipv6("zdp.source_addr_v6", "Source IP Address")
dest_addr_v6 = ProtoField.ipv6("zdp.dest_addr_v6", "Destination IP Address")
ipv4_addr = ProtoField.ipv4("zdp.ipv4", "IP Address")
ipv6_addr = ProtoField.ipv6("zdp.ipv6", "IP Address")
source_info = ProtoField.uint16("zdp.source_info", "Source Port Information", base.DEC)
dest_info = ProtoField.uint16("zdp.dest_info", "Destination Port Information", base.DEC)
status_code = ProtoField.uint8("zdp.status_code", "Status Code", base.DEC)
info_len = ProtoField.uint8("zdp.info_len", "Information Length", base.DEC)
status_info = ProtoField.bytes("zdp.status_info", "Optional Additional Status Information")
comp_mode = ProtoField.uint8("zdp.comp_mode", "Compression Mode", base.HEX)
tlv_type = ProtoField.uint8("zdp.tlv_type", "TLV Type", base.DEC)
tlv_len = ProtoField.uint8("zdp.tlv_length", "TLV Length", base.DEC)
tlv_val_u16 = ProtoField.uint16("zdp.tlv_u16", "TLV Value", base.DEC)
tlv_val_i64 = ProtoField.int64("zdp.tlv_u64", "TLV Value", base.DEC)
tlv_val_str = ProtoField.string("zdp.tlv_string", "TLV Value", base.ASCII)
tlv_val_ipv4 = ProtoField.ipv4("zdp.tlv_ipv4", "TLV Value", base.DEC)
tlv_val_ipv6 = ProtoField.ipv6("zdp.tlv_ipv6", "TLV Value", base.DEC)
tlv_val_bytes = ProtoField.bytes("zdp.tlv_bytes", "TLV Value")
bootstrap_support = ProtoField.uint8("zdp.bootstrap", "Bootstrap Support Flag")
blob_len = ProtoField.uint16("zdp.blob_len", "Blob Length", base.DEC)
addr_count = ProtoField.uint8("zdp.addr_count", "Address Count", base.DEC)
blob = ProtoField.bytes("zdp.blob", "Blob")
nonce = ProtoField.uint64("zdp.nonce", "Nonce", base.HEX)
ctime = ProtoField.uint64("zdp.ctime", "CTime", base.DEC)
-- ip_protocol = ProtoField.uint8("zdp.ip_protocol", "IP Protocol", base.DEC)
-- req_seq_num = ProtoField.uint16("zdp.req_seq_num", "Request Sequence Number", base.DEC)
-- ip_protocol_present = ProtoField.uint8("zdp.protocol_present", "IP Protocol Present", base.DEC)

zdp_proto.fields = { zpi_val, zdp_type, excess_len, seq_num, stream_id, pad, 
                     hmac, a2a_said, agent_packet, a2a_mac, management_packet, ip_version,
                     ihl, frag_id, frag_offset, ttl, tc, fl, hop_limit, trans_id,
                     adl, additional_data, source_port_present, nonce, ctime,
                     dest_port_present, source_addr_v4, source_addr_v6, dest_addr_v4, dest_addr_v6, source_info, 
                     dest_info, status_code, info_len, status_info, reason_code, response_code, data_length_u8, data_length_u16,
                     comp_mode, tlv_type, tlv_len, tlv_val_u16, tlv_val_i64, tlv_val_str, tlv_val_ipv4, 
                     tlv_val_ipv6, tlv_val_bytes, bootstrap_support, blob_len, addr_count, blob, ipv4_addr, ipv6_addr, }
                     --  dscp, ip_options, req_seq_num, ip_protocol_present, ip_protocol

-- Lengths of fields when using Noise Encryption
A2A_SAID = 1
ADDR_COUNT = 1
BOOTSTRAP = 1
COMP_MODE = 1
DL_REPORT = 1
DL_TERMINATE = 1
EXCESS_LEN = 1
FLAGS = 1
HOP_LIMIT = 1
IP_VERSION = 1
INFO_LEN = 1
REASON_CODE = 1
RESPONSE_CODE = 1
TLV_LEN = 1
TLV_TYPE = 1
TTL = 1
TYPE = 1
ZPI = 1

ADL = 2
BIND_TRANS_ID = 2
BLOB_LEN = 2
DL_INIT = 2
FRAG_ID = 2
FRAG_OFFSET = 2

IPV4_LEN = 4
STREAM_ID = 4

A2A_MAC = 8 -- Not sure what the MAC-algorithm-specified-size is (RFC17.2 § 4.2.6.1), but believe zdp.rs 262 specified
CTIME = 8
NONCE = 8
SEQ_NUM = 8

IPV6_LEN = 16

INIT_AUTH_HMAC = 32

HMAC = 0
KEY_NOISE_PAD = 0
TRANS_ID = 0

EXCESS_LEN_START = ZPI + TYPE
TRANSIT_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + SEQ_NUM + STREAM_ID + KEY_NOISE_PAD + HMAC + A2A_SAID + A2A_MAC
PKT_START = TRANSIT_NON_AGENT_DATA - A2A_MAC
PER_FLOW_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + SEQ_NUM + STREAM_ID
NON_FLOW_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + SEQ_NUM

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
    zdp_header:add_field_with_text(zdp_type, TYPE, type_name)
    pinfo.cols.info = type_name

    zdp_header:add_field(excess_len, EXCESS_LEN)

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
    elseif type <= 127 then -- Per-Flow Management Message
        zdp_header:add_field(seq_num, SEQ_NUM)

        zdp_header:add_field(stream_id, STREAM_ID)
        if real_len > PER_FLOW_NON_AGENT_DATA then
            local mgmt_start = zdp_header:get_pos()
            zdp_header:add_field(management_packet, real_len - PER_FLOW_NON_AGENT_DATA)
            decode_management(type, buffer(mgmt_start, real_len - PER_FLOW_NON_AGENT_DATA), tree)
        end
        -- NOTE I believe that both the Pad and the MAC are removed before the packets are captured
    else -- Non-per-flow management message
        -- ARP and Key Mgmt messages do not have a Sequence number
        if type ~= 128 and type ~= 129 then
            zdp_header:add_field(seq_num, SEQ_NUM)
        end

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
    local add_data_len = management:add_field_and_return(adl, ADL)
    if add_data_len > 0 then 
        management:add_field(additional_data, add_data_len)
    end
end

function handle_terminate_ind_req(management)
    if TRANS_ID > 0 then
        management:add_field(trans_id, TRANS_ID)
    end
    management:add_field_with_text_table(reason_code, REASON_CODE, terminate_reason_table)
    local data_len = management:add_field_and_return(data_length_u8, DL_TERMINATE)
    if data_len > 0 then 
        management:add_field(additional_data, data_len)
    end
end

function handle_terminate_res(management)
    if TRANS_ID > 0 then
        management:add_field(trans_id, TRANS_ID)
    end
    management:add_field_with_text_table(response_code, RESPONSE_CODE, response_code_table)
    local data_len = management:add_field_and_return(data_length_u8, DL_TERMINATE)
    if data_len > 0 then 
        management:add_field(additional_data, data_len)
    end
end

function handle_hello_req(management)
    handle_tlvs(management)
end

function handle_hello_res(management)
    management:add_field_with_text_table(response_code, RESPONSE_CODE, response_code_table)
    handle_tlvs(management)
end

function handle_tlvs(management) 
    while management:get_pos() < management:get_buffer_len() do
        local type = management:get_curr_buffer_section(TLV_TYPE):uint()
        management:add_field_with_text_table(tlv_type, TLV_TYPE, tlv_type_table)
        
        if type == 0 then
            goto continue
        end

        local len = management:get_curr_buffer_section(TLV_LEN):uint()
        management:add_field(tlv_len, TLV_LEN)
        
        management:add_field(get_tlv_val_type(type, len), len)

        ::continue::
    end
end

function get_tlv_val_type(type, len) 
    if type == 1 then 
        return tlv_val_i64
    elseif type == 2 then 
        return tlv_val_str
    elseif type == 3 then 
        if len == IPV4_LEN then
            return tlv_val_ipv4
        elseif len == IPV6_LEN then 
            return tlv_val_ipv6
        end
    elseif type == 4 then 
        if len == IPV4_LEN then
            return tlv_val_ipv4
        elseif len == IPV6_LEN then 
            return tlv_val_ipv6
        end
    elseif type == 5 then 
        return tlv_val_bytes
    elseif type == 6 then
        return tlv_val_u16
    end

    return tlv_val_bytes
end

function handle_bind_agent_addr_req(management)
    management:add_field(trans_id, BIND_TRANS_ID)
    local version = management:add_field_and_return(ip_version, IP_VERSION)
    local compression_mode = management:add_field_and_return(comp_mode, COMP_MODE)

    local source_present = get_second_bit(compression_mode)
    local dest_present = get_third_bit(compression_mode)
    management:add_field_with_text_no_buffer(source_port_present, source_present, presence_value[source_present])
    management:add_field_with_text_no_buffer(dest_port_present, dest_present, presence_value[dest_present])

    -- TODO Here we just dissect the src addr and dest addr, do we want other parts of the IP header?
    if version == 4 then
        management:increase_pos(12)
        management:add_field(source_addr_v4, IPV4_LEN)
        management:add_field(dest_addr_v4, IPV4_LEN)
    elseif version == 6 then
        management:increase_pos(8)
        management:add_field(source_addr_v6, IPV6_LEN)
        management:add_field(dest_addr_v6, IPV6_LEN)
    end
    
    if source_present == 1 then
        management:add_field(source_info, PORT_LEN)
    end

    if dest_present == 1 then 
        management:add_field(dest_info, PORT_LEN)
    end
end

function handle_bind_agent_addr_res(management)
    management:add_field(trans_id, BIND_TRANS_ID)
    management:add_field_with_text_table(response_code, RESPONSE_CODE, response_code_table)
    local info = management:add_field_and_return(info_len, INFO_LEN)
    if info > 0 then 
        management:add_field(status_info, info)
    end
end

function handle_init_authentication_req(management) 
    local flags = management:get_curr_buffer_section(FLAGS):uint()
    local bootstrap = get_last_bit(flags)
    management:add_field_with_text(bootstrap_support, BOOTSTRAP, presence_value[bootstrap])
    management:add_field(data_length_u16, DL_INIT)
    management:add_field(nonce, NONCE)
    management:add_field(ctime, CTIME)
    management:add_field(hmac, INIT_AUTH_HMAC)
end

function handle_report(management)
    management:add_field(data_length_u16, DL_REPORT)
end

function handle_acquire_zpr_addr_req(management)
    -- TODO function that adds value AND returns it
    local len = management:add_field_and_return(blob_len, BLOB_LEN)
    local version = management:add_field_and_return(ip_version, IP_VERSION)
    local count = management:add_field_and_return(addr_count, ADDR_COUNT)
    management:add_field(blob, len)

    while management:get_pos() < management:get_buffer_len() do 
        if version == 4 then
            management:add_field(ipv4_addr, IPV4_LEN)
        elseif version == 6 then
            management:add_field(ipv6_addr, IPV6_LEN)
        end
    end
end

function handle_grant_zpr_addr_req(management)
    management:add_field_with_text_table(status_code, RESPONSE_CODE, response_code_table)
    local version = management:add_field_and_return(ip_version, IP_VERSION)
    local count = management:add_field_and_return(addr_count, ADDR_COUNT)

    while management:get_pos() < management:get_buffer_len() do 
        if version == 4 then
            management:add_field(ipv4_addr, IPV4_LEN)
        elseif version == 6 then
            management:add_field(ipv6_addr, IPV6_LEN)
        end
    end
end

-- "Class" that contains the tree, buffer, and current position
function Dissector(init_tree, init_buffer) 
    local dissector = { tree = init_tree, buffer = init_buffer, pos = 0, real_len = 0 }

    local methods = {
        add_field = function(self, field, len)
            self.tree:add(field, self.buffer(self.pos, len))
            self.pos = self.pos + len
        end,
        add_field_and_return = function(self, field, len)
            local val = self.buffer(self.pos, len)
            self.tree:add(field, val)
            self.pos = self.pos + len
            return val:uint()
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
        add_field_with_text_no_buffer = function(self, field, val, text)
            self.tree:add(field, val):append_text(" (" .. text .. ")")
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
        end,
        get_buffer_len = function(self) 
            return self.buffer:len()
        end
    }

    setmetatable(dissector, {__index = methods })
    return dissector
end



-- TODO
-- cleanup existing code

management_table = 
{
    [11] = handle_bind_agent_addr_req,
    [12] = handle_bind_agent_addr_res,
    [131] = handle_echo,
    [133] = handle_terminate_ind_req,
    [134] = handle_terminate_res,
    [135] = handle_terminate_ind_req,
    [136] = handle_hello_req,
    [137] = handle_hello_res,
    [140] = handle_acquire_zpr_addr_req,
    [145] = handle_report,
    [146] = handle_init_authentication_req,
    [148] = handle_grant_zpr_addr_req,
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
    elseif type >= 19 and type <= 95 then type_name = "Unallocated"
    elseif type >= 96 and type <= 126 then type_name = "Reserved for private use and experimentation"
    elseif type >= 150 and type <= 223 then type_name = "Unallocated"
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
    [5] = "Visa Update Request", -- not in rfc
    [6] = "Visa Update Response", -- not in rfc
    [7] = "Visa Retract Request",
    [8] = "Visa Retract Response",
    [9] = "Visa Deaccept Indication", -- differs from rfc
    [10] = "Visa Deaccept Acknowledgement", -- differs from rfc
    [11] = "Bind Actor Address Request",
    [12] = "Bind Actor Address Response",
    [13] = "Unbind Actor Address Request",
    [14] = "Unbind Actor Address Response",
    [15] = "Unused",
    [16] = "Unused",
    [17] = "Set Path MTU",
    [18] = "Unused",
    [127] = "Reserved, Discard", -- not in zdp.rs
    [128] = "ZPR ARP",
    [129] = "Key Management",
    [130] = "Discard",
    [131] = "Echo Request",
    [132] = "Unused", -- not in rfc
    [133] = "Terminate Link Request", -- rfcs also include docking in terminate
    [134] = "Terminate Link Response",
    [135] = "Terminate Link Indication",
    [136] = "Hello Request",
    [137] = "Hello Response",
    [138] = "Configuration Request",
    [139] = "Configuration Response",
    [140] = "Acquire ZPR Address Request",
    [141] = "Unused",
    [142] = "Unused", -- differs from rfc
    [143] = "Unregister Actor Address Request", -- differs from rfc
    [144] = "Unregister Actor Address Response", -- differs from rfc
    [145] = "Report",
    [146] = "Init Authentication Request",
    [147] = "Unused", -- differs from rfc
    [148] = "Grant ZPR Address Request",
    [149] = "Unused", -- differs from rfc
    [254] = "Acknowledgement",
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

tlv_type_table = 
{
    [0] = "NULL",
    [1] = "Policy ID",
    [2] = "Version",
    [3] = "AAA",
    [4] = "ASA",
    [5] = "Static Addr",
    [6] = "Window Size"
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

function get_last_bit(one_byte)
    return bit.band(one_byte, 0x01)
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(1021, zdp_proto)

local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(253, zdp_proto)

local eth_type = DissectorTable.get("ethertype")
eth_type:add(0x88B5, zdp_proto)