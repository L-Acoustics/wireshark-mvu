---
--- mvu_specs.lua
---
--- Constants and information comming from the Milan Specifications related to
--- Milan Vendor Unique data localted in IEEE 1722.1 packets
---

-- Init the module object to return
local m = {}

-----------------------
-- Public Properties --
-----------------------

-- Version of the Milan Specification
m.SPEC_VERSION = "1.2" -- Revision 1.2 of November 29, 2023

-- Protocol ID for MVU
m.PROTOCOL_ID = "001bc50ac100"

-- List of known MVU commands
m.COMMAND_TYPES = {
    GET_MILAN_INFO                 = 0x0000, [0x0000] = "GET_MILAN_INFO",
    SET_SYSTEM_UNIQUE_ID           = 0x0001, [0x0001] = "SET_SYSTEM_UNIQUE_ID",
    GET_SYSTEM_UNIQUE_ID           = 0x0002, [0x0002] = "GET_SYSTEM_UNIQUE_ID",
    SET_MEDIA_CLOCK_REFERENCE_INFO = 0x0003, [0x0003] = "SET_MEDIA_CLOCK_REFERENCE_INFO",
    GET_MEDIA_CLOCK_REFERENCE_INFO = 0x0004, [0x0004] = "GET_MEDIA_CLOCK_REFERENCE_INFO",
}

-- List of known MVU features
m.FEATURE_FLAGS = {
    [0x00000001] = "REDUNDANCY",
    [0x00000002] = "TALKER_DYNAMIC_MAPPINGS_WHILE_RUNNING",
}

-- MVU status codes
m.STATUS_CODES = {
    [0] = "SUCCESS",
    [1] = "NOT_IMPLEMENTED"
}

-- MVU flags for Media Clock Reference
m.MEDIA_CLOCK_REFERENCE_INFO_FLAGS = {
    [0x00000001] = "MEDIA_CLOCK_REFERENCE_PRIORITY_VALID",
    [0x00000002] = "MEDIA_CLOCK_DOMAIN_NAME_VALID",
}

--------------------
-- Public Methods --
--------------------

--- Get the human-readable description of an MVU command type
--- @param command_type number|nil The command type's number
--- @return string command_type_description The human-readable description of the command type
function m.GetCommandTypeDescription(command_type)

    -- Get command type description from list
    local description = m.COMMAND_TYPES[command_type]

    -- If the description was found
    if type(description) == "string"
    then
        -- Return the description
        return description
    -- If the command was not found
    else
        -- Return "Unknown"
        return "Unknown"
    end
end

-- Return the module object
return m
