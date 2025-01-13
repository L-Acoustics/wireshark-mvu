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

MVU.FEATURE_FLAGS = {
    [0x00000001] = "REDUNDANCY",
    [0x00000002] = "TALKER_DYNAMIC_MAPPINGS_WHILE_RUNNING",
}

--- MVU status codes
MVU.STATUS_CODES = {
    [0] = "SUCCESS",
    [1] = "NOT_IMPLEMENTED"
}

-- MVU flags for Media Clock Reference
MVU.MEDIA_CLOCK_REFERENCE_INFO_FLAGS = {
    [0] = "MEDIA_CLOCK_REFERENCE_PRIORITY_VALID",
    [1] = "MEDIA_CLOCK_DOMAIN_NAME_VALID",
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
local f_mvu_command_type                                  = ProtoField.uint32 ("mvu.command_type",                         "Command",                                base.DEC)
local f_mvu_status_code                                   = ProtoField.uint8  ("mvu.status",                               "Status",                                 base.HEX, MVU.STATUS_CODES)
local f_mvu_protocol_version                              = ProtoField.uint32 ("mvu.protocol_version",                     "Protocol Version",                       base.DEC)
local f_mvu_feature_flags                                 = ProtoField.uint32 ("mvu.feature_flags",                        "Feature Flags",                          base.HEX)
local f_mvu_feature_redundancy                            = ProtoField.bool   ("mvu.feature.redundancy",                   "REDUNDANCY",                             32, nil, 0x00000001)
local f_mvu_feature_talker_dynamic_mappings_while_running = ProtoField.bool   ("mvu.feature.talker_dynamic_mappings",      "TALKER_DYNAMIC_MAPPINGS_WHILE_RUNNING",  32, nil, 0x00000002)
local f_mvu_system_unique_id                              = ProtoField.uint32 ("mvu.system_unique_id",                     "System Unique ID",                       base.HEX)
local f_mvu_clock_domain_index                            = ProtoField.uint16 ("mvu.clock_domain_index",                   "Clock Domain Index",                     base.DEC)
local f_mvu_media_clock_reference_flags                   = ProtoField.uint32 ("mvu.media_clock_flags",                    "Media Clock Flags",                      base.HEX)
local f_mvu_media_clock_reference_priority_valid          = ProtoField.bool   ("mvu.media_clock.reference_priority_valid", "REFERENCE PRIORITY VALID",               8, nil, 0x01)
local f_mvu_media_clock_domain_name_valid                 = ProtoField.bool   ("mvu.media_clock.domain_name_valid",        "DOMAIN NAME VALID",                      8, nil, 0x02)
local f_mvu_default_mcr_prio                              = ProtoField.uint8  ("mvu.default_mcr_prio",                     "Default Media Clock Reference Priority", base.DEC)
local f_mvu_user_mcr_prio                                 = ProtoField.uint8  ("mvu.user_mcr_prio",                        "User Media Clock Reference Priority",    base.DEC)
local f_mvu_media_clock_domain_name                       = ProtoField.stringz("mvu.media_clock.domain_name",              "Media Clock Domain Name",                base.UNICODE)

-- Add fields to protocol
milan_proto.fields = {
    f_mvu_command_type,
    f_mvu_status_code,
    f_mvu_protocol_version,
    f_mvu_feature_flags,
    f_mvu_feature_redundancy,
    f_mvu_feature_talker_dynamic_mappings_while_running,
    f_mvu_system_unique_id,
    f_mvu_clock_domain_index,
    f_mvu_media_clock_reference_flags,
    f_mvu_media_clock_reference_priority_valid,
    f_mvu_media_clock_domain_name_valid,
    f_mvu_default_mcr_prio,
    f_mvu_user_mcr_prio,
    f_mvu_media_clock_domain_name,
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
                    --- Status code
                    ---

                    -- Read status code from IEEE1722.1 header
                    local status_code = buffer(16, 1):uint() >> 3

                    -- Write status to the MVU subtree
                    mvuSubtree:add(f_mvu_status_code, buffer(16, 1), status_code)

                    ---
                    --- Responses to GET_MILAN_INFO
                    --- 

                    -- If the message is a reponse to GET_MILAN_INFO
                    if message_type == IEEE17221.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE
                    and (command_type == MVU.COMMAND_TYPES.GET_MILAN_INFO)
                    then
                        -- Read protocol version (4 bytes)
                        local protocol_version = mvu_payload:int(4, 4)

                        -- Write protocol version to the MVU subtree
                        mvuSubtree:add(f_mvu_protocol_version, buffer(mvu_payload_start + 4, 4), protocol_version)

                        -- Read feature flags
                        local feature_flags = mvu_payload:int(8, 4)

                        -- Write feature flags to the MVU subtree
                        mvuSubtree:add(f_mvu_feature_flags, buffer(mvu_payload_start + 8, 4), feature_flags)
                        -- Write individual features flags to the MVU subtree
                        mvuSubtree:add(f_mvu_feature_talker_dynamic_mappings_while_running, buffer(mvu_payload_start + 8, 4))
                        mvuSubtree:add(f_mvu_feature_redundancy, buffer(mvu_payload_start + 8, 4))
                    end

                    ---
                    --- SET_SYSTEM_UNIQUE_ID commands or responses to GET_SYSTEM_UNIQUE_ID
                    --- 

                    -- if the message is a SET_SYSTEM_UNIQUE_ID or a response to GET_SYSTEM_UNIQUE_ID
                    if (message_type == IEEE17221.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND and command_type == MVU.COMMAND_TYPES.SET_SYSTEM_UNIQUE_ID)
                    or (message_type == IEEE17221.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and command_type == MVU.COMMAND_TYPES.GET_SYSTEM_UNIQUE_ID)
                    then
                        -- Get system unique id
                        local system_unique_id = mvu_payload:int(4, 4)

                        -- Write system unique ID to the MVU subtree
                        mvuSubtree:add(f_mvu_system_unique_id, buffer(mvu_payload_start + 4, 4), system_unique_id)
                    end

                    ---
                    --- SET_MEDIA_CLOCK_REFERENCE_INFO commands and responses or responses to GET_MEDIA_CLOCK_REFERENCE_INFO
                    --- 

                    -- If the message is a SET_MEDIA_CLOCK_REFERENCE_INFO command or response or a response to GET_MEDIA_CLOCK_REFERENCE_INFO
                    if (
                        message_type == IEEE17221.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND
                        and command_type == MVU.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO
                    )
                    or
                    (   
                        message_type == IEEE17221.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and
                        (
                            command_type == MVU.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO
                            or command_type == MVU.COMMAND_TYPES.GET_MEDIA_CLOCK_REFERENCE_INFO
                        )
                    )
                    then
                        -- Get clock domain index
                        local clock_domain_index = mvu_payload:int(2, 2)

                        -- Write clock domain index to the MVU subtree
                        mvuSubtree:add(f_mvu_clock_domain_index, buffer(mvu_payload_start + 2, 2), clock_domain_index)

                        -- Get media clock reference info flags
                        local media_clock_reference_info_flags = mvu_payload:int(4, 1)

                        -- Write media clock reference info flags to the MVU subtree
                        mvuSubtree:add(f_mvu_media_clock_reference_flags, buffer(mvu_payload_start + 4, 1), media_clock_reference_info_flags)
                        -- Write individual media clock reference info flags to the MVU subtree
                        mvuSubtree:add(f_mvu_media_clock_reference_priority_valid, buffer(mvu_payload_start + 4, 1))
                        mvuSubtree:add(f_mvu_media_clock_domain_name_valid, buffer(mvu_payload_start + 4, 1))

                        -- Get media clock domain name
                        local media_clock_domain_name = mvu_payload:string(12, 12)
                        
                        -- Write media clock domain name to teh MVU subtree
                        mvuSubtree:add(f_mvu_media_clock_domain_name, buffer(mvu_payload_start + 12, 12), media_clock_domain_name)
                    end
                    
                    ---
                    --- GET_MEDIA_CLOCK_REFERENCE_INFO commands
                    --- 

                    -- If the message is a GET_MEDIA_CLOCK_REFERENCE_INFO command
                    if message_type == IEEE17221.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND and command_type == MVU.COMMAND_TYPES.GET_MEDIA_CLOCK_REFERENCE_INFO
                    then
                        -- Get clock domain index
                        local clock_domain_index = mvu_payload:int(2, 2)

                        -- Write clock domain index to the MVU subtree
                        mvuSubtree:add(f_mvu_clock_domain_index, buffer(mvu_payload_start + 2, 2), clock_domain_index)
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
