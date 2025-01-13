-- Constants

--- Protocol ID for MVU
local MVU_PROTOCOL_ID = "001bc50ac100"

--- List of known command types
local COMMAND_TYPES = {
    GET_MILAN_INFO = 0x0000, [0x0000] = "GET_MILAN_INFO"
}

-- Create proto object for the dissector
local milan_proto = Proto("mvu", "Milan Vendor Unique (MVU)")

-- Declare fields to be read
local f_ieee17221_control_data_length = Field.new("ieee17221.control_data_length")
local f_ieee17221_message_type = Field.new("ieee17221.message_type")
local f_ieee17221_vendor_unique_protocol_id = Field.new("ieee17221.protocol_id")

-- Declare new fields
local f_milan_command_type = ProtoField.int32("mvu.command_type", "Command", base.DEC)

-- Add fields to protocol
milan_proto.fields = { f_milan_command_type }

--- Implementation of protocol's dissector
--- @param buffer any
--- @param pinfo any
--- @param tree any
function milan_proto.dissector(buffer, pinfo, tree)

    -- Read fields
    local ieee17221_control_data_length = f_ieee17221_control_data_length()
    local ieee17221_message_type = f_ieee17221_message_type()
    local ieee17221_vendor_unique_protocol_id = f_ieee17221_vendor_unique_protocol_id()

    -- Check fields presence
    if  ieee17221_control_data_length
    and ieee17221_message_type
    and ieee17221_vendor_unique_protocol_id
    then
        -- Check field types
        if  ieee17221_control_data_length.type       == 5 -- number
        and ieee17221_message_type.type              == 4 -- number
        and ieee17221_vendor_unique_protocol_id.type == 9 -- byte array
        then
            local control_data_length = ieee17221_control_data_length.value
            -- Get message type
            local message_type = ieee17221_message_type.value
            -- Read vendor protocol ID
            local vendor_unique_protocol_id = ieee17221_vendor_unique_protocol_id.range:bytes():tohex(true)

            -- Check field values
            if vendor_unique_protocol_id == MVU_PROTOCOL_ID then

                -- If packet visited
                if pinfo.visited then
                    -- Get MVU payload bytes from buffer
                    -- Skip:
                    --   14 bytes for Ethernet header
                    --   4 bytes for IEEE1722 subtype
                    --   8 bytes for IEEE1722 stream ID
                    --   8 bytes for IEEE1722.1 controller ID
                    --   2 bytes for IEEE1722.1 sequence ID
                    --   6 bytes for IEEE1722.1 vendor protocol ID
                    -- Note: the control_data_length includes IEEE1722.1 headers so the MVU payload size is the control data length - IEEE1722.1 headers length (16 bytes)
                    local mvu_payload_start = 14 + 4 + 8 + 8 + 2 + 6
                    local mvu_payload_length = control_data_length - 16
                    local mvu_payload = buffer:bytes(mvu_payload_start, mvu_payload_length)

                    -- Add MVU subtree to packet details
                    local milanSubtree = tree:add(milan_proto, buffer(42, control_data_length - 16), "Milan Vendor Unique (MVU)")

                    -- Read command type (2 bytes, ignoring first bit)
                    local command_type = 0x7fff & mvu_payload:int(0, 2)
                    -- Get command type description
                    local command_type_description = GetCommandTypeDescription(command_type)

                    -- Write command type and description to the MVU subtree
                    milanSubtree:add(f_milan_command_type, buffer(42, 2), command_type):append_text(" (" .. command_type_description .. ")")
                end

            end
        end
    end
end

-- Finally, register protocol as a postdissector
register_postdissector(milan_proto)

--- Get the human-readable description of an MVU command type
--- @param command_type number The command type's number
--- @return string command_type_description The human-readable description of the command type
function GetCommandTypeDescription(command_type)

    -- Get command type description from list
    local description = COMMAND_TYPES[command_type]

    -- If the description was found
    if type(description) == "string" then
        -- Return the description
        return description
    -- If the command was not found
    else
        -- Return "Unknown"
        return "Unknown"
    end
end
