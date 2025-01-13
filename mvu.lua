---------------
-- CONSTANTS --
---------------
---
-- Version of this plugin
VERSION = "1.0.0.0"

-- MVU constants
MVU = {}

-- Version of the Milan Specification
MVU.SPEC_VERSION = "1.2" -- Revision 1.2 of November 29, 2023

--- Protocol ID for MVU
MVU.PROTOCOL_ID = "001bc50ac100"

--- List of known MVU commands
MVU.COMMAND_TYPES = {
    GET_MILAN_INFO                 = 0x0000, [0x0000] = "GET_MILAN_INFO",
    SET_SYSTEM_UNIQUE_ID           = 0x0001, [0x0001] = "SET_SYSTEM_UNIQUE_ID",
    GET_SYSTEM_UNIQUE_ID           = 0x0002, [0x0002] = "GET_SYSTEM_UNIQUE_ID",
    SET_MEDIA_CLOCK_REFERENCE_INFO = 0x0003, [0x0003] = "SET_MEDIA_CLOCK_REFERENCE_INFO",
    GET_MEDIA_CLOCK_REFERENCE_INFO = 0x0004, [0x0004] = "GET_MEDIA_CLOCK_REFERENCE_INFO",
}

--- MVU status codes
MVU.STATUS_CODES = {
    SUCCESS         = 0, [0] = "SUCCESS",
    NOT_IMPLEMENTED = 1, [1] = "NOT_IMPLEMENTED"
}

-- IEEE 1722.1 constants
IEEE17221 = {}

--- List of known IEEE 1722.1 AECP commands
IEEE17221.AECP_MESSAGE_TYPES = {
    VENDOR_UNIQUE_COMMAND  = 6, [6] = "VENDOR_UNIQUE_COMMAND",
    VENDOR_UNIQUE_RESPONSE = 7, [7] = "VENDOR_UNIQUE_RESPONSE",
}

-- Create proto object for the dissector
local milan_proto = Proto("mvu", "Milan Vendor Unique (MVU)")

-- Declare fields to be read
local f_ieee17221_control_data_length = Field.new("ieee17221.control_data_length")
local f_ieee17221_message_type = Field.new("ieee17221.message_type")
local f_ieee17221_vendor_unique_protocol_id = Field.new("ieee17221.protocol_id")

-- Declare new fields
local f_mvu_command_type = ProtoField.int32("mvu.command_type", "Command", base.DEC)
local f_mvu_protocol_version = ProtoField.int32("mvu.protocol_version", "Protocol Version", base.DEC)

-- Add fields to protocol
milan_proto.fields = {
    f_mvu_command_type,
    f_mvu_protocol_version,
}

--- Implementation of protocol's dissector
--- @param buffer string The buffer to dissect
--- @param pinfo table The packet info
--- @param tree table The tree on which to add the procotol items
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
            if vendor_unique_protocol_id == MVU.PROTOCOL_ID then

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
                    local mvu_payload_start = 14 + 4 + 8 + 8 + 2 + 6
                    -- Note: the control_data_length includes IEEE1722.1 headers so the MVU payload size is the control data length - IEEE1722.1 headers length (16 bytes)
                    local mvu_payload_length = control_data_length - 16
                    local mvu_payload = buffer:bytes(mvu_payload_start, mvu_payload_length)

                    -- Add MVU subtree to packet details
                    local mvuSubtree = tree:add(milan_proto, buffer(42, control_data_length - 16), "Milan Vendor Unique (MVU)")

                    ---
                    --- Command Type
                    ---

                    -- Read command type (2 bytes, ignoring first bit)
                    local command_type = 0x7fff & mvu_payload:int(0, 2)
                    -- Get command type description
                    local command_type_description = GetCommandTypeDescription(command_type)

                    -- Write command type and description to the MVU subtree
                    mvuSubtree:add(f_mvu_command_type, buffer(mvu_payload_start, 2), command_type):append_text(" (" .. command_type_description .. ")")

                    ---
                    --- Protocol version (in responses to GET_MILAN_INFO or GET_SYSTEM_UNIQUE_ID)
                    --- 
                    
                    -- If the message is a reponse to GET_MILAN_INFO or GET_SYSTEM_UNIQUE_ID
                    if message_type == IEEE17221.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE
                    and (command_type == MVU.COMMAND_TYPES.GET_MILAN_INFO or command_type == MVU.COMMAND_TYPES.GET_SYSTEM_UNIQUE_ID)
                    then
                        -- Read protocol version (4 bytes)
                        local protocol_version = mvu_payload:int(4, 4)

                        -- Write protocol version to the MVU subtree
                        mvuSubtree:add(f_mvu_protocol_version, buffer(mvu_payload_start + 4, 4), protocol_version)
                    end
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
    local description = MVU.COMMAND_TYPES[command_type]

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
