-- Custom Wireshark Lua Dissector for FinTech SOC ISO 8583 Switch Protocol (TCP Port 8583)
iso8583_proto = Proto("ISO8583", "ISO 8583 Financial Transaction Protocol (FinTech SOC)")

local f_len   = ProtoField.string("iso8583.length", "Frame Length Prefix")
local f_mti   = ProtoField.string("iso8583.mti", "Message Type Indicator (MTI)")
local f_de2   = ProtoField.string("iso8583.de2", "DE 2  - Primary Account Number (PAN)")
local f_de3   = ProtoField.string("iso8583.de3", "DE 3  - Processing Code")
local f_de4   = ProtoField.string("iso8583.de4", "DE 4  - Transaction Amount (Cents)")
local f_de7   = ProtoField.string("iso8583.de7", "DE 7  - Transmission Date & Time")
local f_de11  = ProtoField.string("iso8583.de11", "DE 11 - System Trace Audit Number (STAN)")
local f_de37  = ProtoField.string("iso8583.de37", "DE 37 - Retrieval Reference / Trace ID")
local f_de39  = ProtoField.string("iso8583.de39", "DE 39 - Response Code")
local f_de54  = ProtoField.string("iso8583.de54", "DE 54 - Additional Amounts (Balance Cents)")
local f_de102 = ProtoField.string("iso8583.de102", "DE 102 - Source Account ID")
local f_de103 = ProtoField.string("iso8583.de103", "DE 103 - Destination Account ID")

iso8583_proto.fields = {
    f_len, f_mti, f_de2, f_de3, f_de4, f_de7,
    f_de11, f_de37, f_de39, f_de54, f_de102, f_de103
}

function iso8583_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 12 then return end

    local raw_str = buffer(0, length):string()
    if not string.find(raw_str, "ISO8583|") then return end

    pinfo.cols.protocol = "ISO-8583"
    local subtree = tree:add(iso8583_proto, buffer(), "ISO 8583 Financial Switch Message")

    local len_prefix = string.sub(raw_str, 1, 4)
    local payload = string.sub(raw_str, 5):gsub("[\r\n]+", "")
    subtree:add(f_len, buffer(0, 4), len_prefix)

    local parts = {}
    for part in string.gmatch(payload, "([^|]+)") do
        table.insert(parts, part)
    end

    local mti = parts[2] or "UNKNOWN"
    subtree:add(f_mti, mti)

    local de39_val = ""
    local trace_val = ""
    for i = 3, #parts do
        local k, v = string.match(parts[i], "([^=]+)=(.*)")
        if k and v then
            if k == "DE2" then subtree:add(f_de2, v)
            elseif k == "DE3" then subtree:add(f_de3, v)
            elseif k == "DE4" then subtree:add(f_de4, v)
            elseif k == "DE7" then subtree:add(f_de7, v)
            elseif k == "DE11" then subtree:add(f_de11, v)
            elseif k == "DE37" then subtree:add(f_de37, v); trace_val = v
            elseif k == "DE39" then subtree:add(f_de39, v); de39_val = v
            elseif k == "DE54" then subtree:add(f_de54, v)
            elseif k == "DE102" then subtree:add(f_de102, v)
            elseif k == "DE103" then subtree:add(f_de103, v)
            end
        end
    end

    if de39_val ~= "" then
        pinfo.cols.info = "ISO 8583 MTI " .. mti .. " [Resp DE39=" .. de39_val .. "] Trace=" .. trace_val
    else
        pinfo.cols.info = "ISO 8583 MTI " .. mti .. " [Request] Trace=" .. trace_val
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8583, iso8583_proto)