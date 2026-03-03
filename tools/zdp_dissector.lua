-- Dissector for ZDP Packet

zdp_proto = Proto("zdp", "ZDP Header Dissector")

-- ZDP Headers 
local a2a_mac = ProtoField.uint64("zdp.a2a_mac", "A2A MAC", base.HEX)
local a2a_said = ProtoField.uint8("zdp.a2a_said", "A2A SAID", base.HEX)
local agent_packet = ProtoField.bytes("zdp.agent_packet", "Agent Packet")
local excess_len = ProtoField.uint8("zdp.excess_len", "Excess Length", base.DEC)
local hmac = ProtoField.bytes("zdp.mac", "HMAC")
local management_packet = ProtoField.bytes("zdp.management", "Management Packet")
local pad = ProtoField.bytes("zdp.pad", "Pad")
local seq_num = ProtoField.uint64("zdp.seq_num", "Sequence Number", base.DEC)
local stream_id = ProtoField.uint32("zdp.streamid", "Stream ID", base.DEC)
local zdp_type = ProtoField.uint8("zdp.type", "Type", base.DEC)
local zpi_val = ProtoField.uint8("zdp.zpi", "ZPI", base.DEC)

-- Agent Packet Headers
local fl = ProtoField.uint32("zdp.fl", "Flow Label", base.DEC)
local frag_id = ProtoField.uint16("zdp.frag_id", "Fragment ID", base.DEC)
local frag_offset = ProtoField.uint16("zdp.frag_offset", "Fragment Offset", base.DEC)
local hop_limit = ProtoField.uint8("zdp.hop_limit", "Hop Limit", base.DEC)
local ihl = ProtoField.uint8("zdp.ihl", "Internet Header Length", base.DEC)
local ip_version = ProtoField.uint8("zdp.ip_version", "IP Version", base.DEC)
local tc = ProtoField.uint8("zdp.tc", "Traffic Class", base.DEC)
local ttl = ProtoField.uint8("zdp.ttl", "Time to Live", base.DEC)
-- dscp = ProtoField.uint8("zdp.dscp", "Differentiated Services Code Point", base.DEC)
-- ip_options = ProtoField.bytes("zdp.ip_options", "IP Options")

-- Management Data
local additional_data = ProtoField.bytes("zdp.additional", "Optional Additional Data")
local addr_count = ProtoField.uint8("zdp.addr_count", "Address Count", base.DEC)
local adl = ProtoField.uint16("zdp.adl", "Additional Data Length", base.DEC)
local blob = ProtoField.bytes("zdp.blob", "Blob")
local blob_len = ProtoField.uint16("zdp.blob_len", "Blob Length", base.DEC)
local bootstrap_support = ProtoField.uint8("zdp.bootstrap", "Bootstrap Support Flag")
local comp_mode = ProtoField.uint8("zdp.comp_mode", "Compression Mode", base.HEX)
local ctime = ProtoField.uint64("zdp.ctime", "CTime", base.DEC)
local data_length_u8 = ProtoField.uint8("zdp.data_len_t", "Data Length", base.DEC)
local data_length_u16 = ProtoField.uint16("zdp.data_len_i", "Data Length", base.DEC)
local dest_addr_v4 = ProtoField.ipv4("zdp.dest_addr_v4", "Destination IP Address")
local dest_addr_v6 = ProtoField.ipv6("zdp.dest_addr_v6", "Destination IP Address")
local dest_info = ProtoField.uint16("zdp.dest_info", "Destination Port Information", base.DEC)
local info_len = ProtoField.uint8("zdp.info_len", "Information Length", base.DEC)
local ip_protocol = ProtoField.uint8("zdp.ip_protocol", "IP Protocol", base.DEC)
local ipv4_addr = ProtoField.ipv4("zdp.ipv4", "IP Address")
local ipv6_addr = ProtoField.ipv6("zdp.ipv6", "IP Address")
local nonce = ProtoField.uint64("zdp.nonce", "Nonce", base.HEX)
local pkt_len = ProtoField.uint16("zdp.pkt_len", "Endpoint Packet Length", base.DEC)
local reason_code = ProtoField.uint8("zdp.reason_code", "Reason Code", base.DEC)
local response_code = ProtoField.uint8("zdp.response_code", "Response Code", base.DEC)
local source_addr_v4 = ProtoField.ipv4("zdp.source_addr_v4", "Source IP Address")
local source_addr_v6 = ProtoField.ipv6("zdp.source_addr_v6", "Source IP Address")
local source_info = ProtoField.uint16("zdp.source_info", "Source Port Information", base.DEC)
local status_code = ProtoField.uint8("zdp.status_code", "Status Code", base.DEC)
local status_info = ProtoField.bytes("zdp.status_info", "Optional Additional Status Information")
local tcst = ProtoField.uint8("zdp.tcst", "TCST", base.DEC)
local tlv_len = ProtoField.uint8("zdp.tlv_length", "TLV Length", base.DEC)
local tlv_type = ProtoField.uint8("zdp.tlv_type", "TLV Type", base.DEC)
local tlv_val_bytes = ProtoField.bytes("zdp.tlv_bytes", "TLV Value")
local tlv_val_i64 = ProtoField.int64("zdp.tlv_i64", "TLV Value", base.DEC)
local tlv_val_ipv4 = ProtoField.ipv4("zdp.tlv_ipv4", "TLV Value", base.DEC)
local tlv_val_ipv6 = ProtoField.ipv6("zdp.tlv_ipv6", "TLV Value", base.DEC)
local tlv_val_str = ProtoField.string("zdp.tlv_string", "TLV Value", base.ASCII)
local tlv_val_u16 = ProtoField.uint16("zdp.tlv_u16", "TLV Value", base.DEC)
local trans_id = ProtoField.uint16("zdp.trans_id", "Transaction ID", base.DEC)
-- dest_port_present = ProtoField.uint8("zdp.dest_port_present", "Destination Port Information Present", base.DEC)
-- ip_protocol_present = ProtoField.uint8("zdp.protocol_present", "IP Protocol Present", base.DEC)
-- req_seq_num = ProtoField.uint16("zdp.req_seq_num", "Request Sequence Number", base.DEC)
-- source_port_present = ProtoField.uint8("zdp.source_port_present", "Source Port Information Present", base.DEC)

-- Request/response matching
local req_frame = ProtoField.framenum("zdp.request_frame", "Request", base.NONE, frametype.REQUEST)
local res_frame = ProtoField.framenum("zdp.response_frame", "Response", base.NONE, frametype.RESPONSE)


local acked_frame = ProtoField.framenum("zdp.ack_frame", "Acknowledged", base.NONE, frametype.ACK)
local acked_by_frame = ProtoField.framenum("zdp.acked_by", "Acknowledged By", base.NONE, frametype.ACK)


zdp_proto.fields = { 
    -- ZDP Headers
    a2a_mac, a2a_said, agent_packet, excess_len, hmac, management_packet, pad,
    seq_num, stream_id, zdp_type, zpi_val,
    -- Agent Packet Headers
    fl, frag_id, frag_offset, hop_limit, ihl, ip_version, tc, ttl,
    -- Management Data
    additional_data, addr_count, adl, blob, blob_len, bootstrap_support, comp_mode,
    ctime, data_length_u8, data_length_u16, dest_addr_v4, dest_addr_v6, dest_info, 
    ip_protocol, info_len, ipv4_addr, ipv6_addr, nonce, pkt_len, 
    reason_code,  response_code, source_addr_v4, source_addr_v6, source_info, 
    status_code, status_info, tcst, tlv_len, tlv_type, tlv_val_bytes, 
    tlv_val_i64, tlv_val_ipv4, tlv_val_ipv6, tlv_val_str, tlv_val_u16, trans_id,
    req_frame, res_frame, acked_frame, acked_by_frame
}

-- Lengths of fields when using Noise Encryption
local A2A_SAID = 1
local ADDR_COUNT = 1
local BOOTSTRAP = 1
local COMP_MODE = 1
local DL_REPORT = 1
local DL_TERMINATE = 1
local EXCESS_LEN = 1
local FLAGS = 1
local HOP_LIMIT = 1
local IP_VERSION = 1
local IP_PROTOCOL = 1
local INFO_LEN = 1
local REASON_CODE = 1
local RESPONSE_CODE = 1
local TC = 1
local TCST = 1
local TLV_LEN = 1
local TLV_TYPE = 1
local TTL = 1
local TYPE = 1
local ZPI = 1

local ADL = 2
local PKT_LEN = 2
local BLOB_LEN = 2
local DL_INIT = 2
local FRAG_ID = 2
local FRAG_OFFSET = 2
local TRANS_ID = 2

local IPV4_LEN = 4
local STREAM_ID = 4

local A2A_MAC = 8 -- Not sure what the MAC-algorithm-specified-size is (RFC17.2 § 4.2.6.1), but believe zdp.rs 262 specified
local CTIME = 8
local NONCE = 8
local SEQ_NUM = 8

local IPV6_LEN = 16

local INIT_AUTH_HMAC = 32

local HMAC = 0
local KEY_NOISE_PAD = 0

local EXCESS_LEN_START = ZPI + TYPE
local TRANSIT_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + STREAM_ID + KEY_NOISE_PAD + HMAC + A2A_SAID + A2A_MAC
local PKT_START = TRANSIT_NON_AGENT_DATA - A2A_MAC
local PER_FLOW_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + SEQ_NUM + STREAM_ID
local NON_FLOW_NON_AGENT_DATA = ZPI + TYPE + EXCESS_LEN + SEQ_NUM

local req_frames = {}     -- stream id -> request frame
local res_frames = {}     -- request frame -> response frame
local seq_to_frame = {}   -- seq_num -> frame that sent it
local ack_links = {}      -- frame -> paired frame (bidirectional)

function zdp_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = zdp_proto.name

    -- TODO shorten main    
    local zdp_header_subtree = tree:add(zdp_proto, buffer(), "ZDP Header Data")

    local zdp_header = TreeBuilder(buffer, pinfo, zdp_header_subtree)
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
        local agent_header = TreeBuilder(buffer, pinfo, agent_header_subtree)
        agent_header:set_pos(PKT_START)
        local v4_v6 = get_first_four(buffer(PKT_START, 1):uint())
        agent_header:add_field_no_buffer(ip_version, v4_v6)

        -- NOTE/TODO No updates to this section RE size/position of values, assuming they stayed the same for now
        -- Just want to get this somewhat working first
        if v4_v6 == 4 then
            -- TODO since the curr_pos always has to get incremented, perhaps make a func that both adds to tree and increments curr_pos
            local ihl_val = get_back_four(buffer(PKT_START, 1):uint())
            agent_header:add_field_no_buffer(ihl, ihl_val)
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
            agent_header:add_field_no_buffer(tc, tc_value)
            curr_pos = curr_pos + 1
            local fl_value = get_back_twelve(buffer(curr_pos, 3):uint())
            agent_header:add_field_no_buffer(fl, fl_value)
            curr_pos = curr_pos + 2
            agent_header:add_field_no_buffer(hop_limit, buffer(curr_pos, HOP_LIMIT):uint())
            -- Dissector.get("tcp"):call(buffer(15, real_len - IP_NON_AGENT_DATA):tvb(), pinfo, tree)
        end
    elseif type <= 127 then -- Per-Flow Management Message
        local sequence_num = tostring(zdp_header:add_field_and_return_u64(seq_num, SEQ_NUM))
        ack_linking(type, zdp_header, sequence_num)

        zdp_header:add_field(stream_id, STREAM_ID)
        if real_len > PER_FLOW_NON_AGENT_DATA then
            local mgmt_start = zdp_header:get_pos()
            zdp_header:add_field(management_packet, real_len - PER_FLOW_NON_AGENT_DATA)
            decode_management(type, buffer(mgmt_start, real_len - PER_FLOW_NON_AGENT_DATA), pinfo, tree)
        end
        -- NOTE I believe that both the Pad and the MAC are removed before the packets are captured
    else -- Non-per-flow management message
        -- ARP and Key Mgmt messages do not have a Sequence number
        if type ~= 128 and type ~= 129 then
            local sequence_num = tostring(zdp_header:add_field_and_return_u64(seq_num, SEQ_NUM))

            ack_linking(type, zdp_header, sequence_num)
        end

        if real_len > NON_FLOW_NON_AGENT_DATA then
            local mgmt_start = zdp_header:get_pos()
            zdp_header:add_field(management_packet, real_len - NON_FLOW_NON_AGENT_DATA)
            decode_management(type, buffer(mgmt_start, real_len - NON_FLOW_NON_AGENT_DATA), pinfo, tree)
        end
    end
end

-- Idiomatic way of doing this may be to actually create a whole new dissector, although that might be challenging
-- becuase we couldn't just forward the managament packet, the type would also have to be forwarded, meaning we would either
-- have to forward basically the whole packet, or create a new tvb with the type and the management packet and forward that
function decode_management(type, buffer, pinfo, tree)
    local management_subtree = tree:add(zdp_proto, buffer(), "Management Packet Data")
    local management = TreeBuilder(buffer, pinfo, management_subtree)
    local func = management_table[type]
    if(func) then
        func(management)
    else
        management_subtree:add(management_packet, buffer(0))
    end
end

-- Function definitions must come before table
function handle_echo(management)
    local add_data_len = management:add_field_and_return(adl, ADL)
    if add_data_len > 0 then 
        management:add_field(additional_data, add_data_len)
    end
end

function handle_terminate_ind_req(management)
    management:add_field_with_text_table(reason_code, REASON_CODE, terminate_reason_table)
    local data_len = management:add_field_and_return(data_length_u8, DL_TERMINATE)
    if data_len > 0 then 
        management:add_field(additional_data, data_len)
    end
end

function handle_terminate_res(management)
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

function handle_bind_actor_addr_req(management)
    local transaction_id = management:add_field_and_return(trans_id, TRANS_ID)

    add_request_frame(management, transaction_id)

    local version = management:add_field_and_return(ip_version, IP_VERSION)
    local length = management:add_field_and_return(pkt_len, PKT_LEN)

    -- Save ZDP column info before handing off to IP dissector
    local saved_pinfo = save_pinfo(management:get_pinfo())

    -- Full IP packet inside, can just hand off to IP dissector
    local ip_dissector = Dissector.get("ip")
    ip_dissector:call(management:get_curr_buffer_section(length):tvb(), management:get_pinfo(), management:get_tree())

    -- Restore ZDP column info
    restore_pinfo(saved_pinfo, management)
end

function handle_bind_actor_addr_res(management)
    local transaction_id = management:add_field_and_return(trans_id, TRANS_ID)
    
    add_response_link(management, transaction_id)

    management:add_field_with_text_table(response_code, RESPONSE_CODE, response_code_table)
    local info = management:add_field_and_return(info_len, INFO_LEN)
    if info > 0 then 
        management:add_field(status_info, info)
    end
    management:add_field(tcst, TCST)
    management:add_field(tc, TC)
end

function handle_bind_egress_stream_req(management)
    local transaction_id = management:add_field_and_return(trans_id, TRANS_ID)
    add_request_frame(management, transaction_id)
    management:add_field(tcst, TCST)
    management:add_field(tc, TC)
end

function handle_bind_egress_stream_res(management)
    local transaction_id = management:add_field_and_return(trans_id, TRANS_ID)
    add_response_link(management, transaction_id)    
    management:add_field_with_text_table(response_code, RESPONSE_CODE, response_code_table)
    management:add_field(info_len, INFO_LEN)
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
function TreeBuilder(init_buffer, init_pinfo, init_tree) 
    local dissector = { buffer = init_buffer, pinfo = init_pinfo, tree = init_tree, pos = 0, real_len = 0 }

    local methods = {
        add_field = function(self, field, len)
            self.tree:add(field, self.buffer(self.pos, len))
            self.pos = self.pos + len
        end,
        add_field_no_buffer = function(self, field, val)
            self.tree:add(field, val)
        end,
        add_field_and_return = function(self, field, len)
            local val = self.buffer(self.pos, len)
            self.tree:add(field, val)
            self.pos = self.pos + len
            return val:uint()
        end,
        add_field_and_return_u64 = function(self, field, len)
            local val = self.buffer(self.pos, len)
            self.tree:add(field, val)
            self.pos = self.pos + len
            return val:uint64()
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
        end,
        get_pinfo = function(self)
            return self.pinfo
        end,
        get_tree = function(self)
            return self.tree
        end,
        get_frame_num = function(self)
            return self.pinfo.number
        end,
        is_visited = function(self)
            return self.pinfo.visited
        end
    }

    setmetatable(dissector, {__index = methods })
    return dissector
end

management_table = 
{
    [6] = handle_bind_actor_addr_req,
    [7] = handle_bind_actor_addr_res,
    [8] = handle_bind_egress_stream_req,
    [9] = handle_bind_egress_stream_res,
    [131] = handle_echo,
    [133] = handle_terminate_ind_req,
    [142] = handle_terminate_res,
    [143] = handle_terminate_ind_req,
    [134] = handle_hello_req,
    [135] = handle_hello_res,
    [138] = handle_acquire_zpr_addr_req,
    [132] = handle_report,
    [141] = handle_init_authentication_req,
    [139] = handle_grant_zpr_addr_req,
}

presence_value = 
{
    [0] = "Not Present",
    [1] = "Present",
}

function add_request_frame(management, transaction_id)
    local frame_num = management:get_frame_num()
    if not management:is_visited() then
        req_frames[transaction_id] = frame_num
    end

    local res = res_frames[frame_num]
    if res then 
        management:add_field_no_buffer(res_frame, res)
    end
end

function add_response_link(management, transaction_id)
    local frame_num = management:get_frame_num()
    if not management:is_visited() then
        local req = req_frames[transaction_id]
        if req then 
            res_frames[req] = frame_num -- req -> res
            res_frames[frame_num] = req -- res -> req
        end
    end
    local req = res_frames[frame_num]
    if req then
        management:add_field_no_buffer(req_frame, req)
    end
end

function ack_linking(type, zdp_header, sequence_num)
    local frame_num = zdp_header:get_frame_num()
    if not zdp_header:is_visited() then
        if not no_ack[type] then
            seq_to_frame[sequence_num] = frame_num
        end
    end

    if type == 254 then
        if not zdp_header:is_visited() then
            local acked_pkt = seq_to_frame[sequence_num]
            if acked_pkt then
                ack_links[acked_pkt] = frame_num    -- original -> ack
                ack_links[frame_num] = acked_pkt    -- ack -> original
            end
        end
    end

    local linked = ack_links[frame_num]
    if linked then
        if type == 254 then
            zdp_header:add_field_no_buffer(acked_frame, linked)
        elseif not no_ack[type] then
            zdp_header:add_field_no_buffer(acked_by_frame, linked)
        end
    end
end

function save_pinfo(pinfo) 
    local p = {}
    -- The src and dst are set in link_header_dissector, so it can't be saved here.
    -- Would have to change the way we approach the handoff, would not be a major 
    -- change, I don't think
    -- p.dst = tostring(pinfo.cols.dst)
    -- p.src = tostring(pinfo.cols.src)
    p.protocol = tostring(pinfo.cols.protocol)
    p.info = tostring(pinfo.cols.info)

    return p
end

function restore_pinfo(pinfo, management)
    -- management:get_pinfo().cols.src = pinfo.src
    -- management:get_pinfo().cols.dst = pinfo.dst
    management:get_pinfo().cols.protocol = pinfo.protocol
    management:get_pinfo().cols.info = pinfo.info
end
-- Gets type name for a packet using the table below. Will return nil if type is 
-- not between 0 and 254
function get_type_name(type)
    local type_name = type_name_table[type]

    if type_name ~= nil then return type_name
    elseif type >= 10 and type <= 95 then type_name = "Unallocated"
    elseif type >= 96 and type <= 126 then type_name = "Reserved: Experimental and Private Use"
    elseif type >= 142 and type <= 223 then type_name = "Unallocated"
    elseif type >= 224 and type <= 253 then type_name = "Reserved: Experimental and Private Use" end

    return type_name
end 

type_name_table =
{
    [0] = "Transit Packet",
    [1] = "Destination Unreachable",
    [2] = "Set Path MTU",
    [3] = "Stream ID Request",
    [4] = "Stream ID Response",
    [5] = "Stream ID Withdrawal",
    [6] = "Bind Actor Address Request",
    [7] = "Bind Actor Address Response",
    [8] = "Bind Egress Stream Request",
    [9] = "Bind Egress Stream Response",
    [13] = "Unbind Egress Stream Indication",
    [127] = "Reserved: Must not be used",
    [128] = "ZPR ARP",
    [129] = "Key Management",
    [130] = "Discard",
    [131] = "Echo",
    [132] = "Report",
    [133] = "Terminate Link or Docking Session",
    [134] = "Hello Request",
    [135] = "Hello Response",
    [136] = "Configuration Request",
    [137] = "Configuration Response",
    [138] = "Acquire ZPR Address",
    [139] = "Grant ZPR Address",
    [140] = "Revoke ZPR Address",
    [141] = "Init Authentication Request",
    [254] = "Acknowledgement",
    [255] = "Reserved: Must not be used",
}

terminate_reason_table =
{
    [0] = "Other",
    [1] = "Unused",
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

-- The only packets that don't get ack'd are Transit Packets, Arp, Key Management, and Acknowledgements
no_ack = 
{
    [0] = true,
    [128] = true,
    [129] = true,
    [254] = true
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