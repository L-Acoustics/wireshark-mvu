---
--- mvu_specs.lua
---
--- Constants and information comming from the Milan Specifications related to
--- Milan Vendor Unique data localted in IEEE 1722.1 packets
---

-- Require dependency modules
local mIEEE17221Specs = require("ieee17221_specs")

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

--- Get the version of Milan specification implemented by the provided command or response
--- @param message_type number|nil The type of message (as defined in IEEE1722.1 AECP_MESSAGE_TYPES enum)
--- @param command_type number|nil The type of command (ad defined in MVU COMMAND_TYPES enum)
--- @param control_data_length number|nil The value of the Copntrol Data Length field of the packet holding the command
--- @return string|nil milan_version Milan specification revision number. nil if version is unknown
--- @return boolean|nil unimplemented_extra_bytes Indicates if there are bytes at the end of the payload that are not implemented by this plugin
function m.GetMilanVersionOfCommand(message_type, command_type, control_data_length)

	-- GET_MILAN_INFO
	if command_type == m.COMMAND_TYPES.GET_MILAN_INFO then

		-- Command
		if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND then
			-- Version 1.1 (CDL = 20)
			if control_data_length >= 20 then
				-- Version 1.1, extra bytes if control_data_length is strictly greater
				return "1.1", (control_data_length > 20)
			end

		-- Response
		elseif message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE then
			-- Version 1.1a (CDL = 32)
			if control_data_length >= 32 then
				-- Version 1.1, extra bytes if control_data_length is strictly greater
				return "1.1", (control_data_length > 32)
			end
		end

	-- SET_SYSTEM_UNIQUE_ID
	elseif command_type == m.COMMAND_TYPES.SET_SYSTEM_UNIQUE_ID then

		-- Command
		if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND then
			-- Version 1.2 (CDL = 24)
			if control_data_length >= 24 then
				-- Version 1.2, extra bytes if control_data_length is strictly greater
				return "1.2", (control_data_length > 24)
			end

		-- Response
		elseif message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE then
			-- Version 1.2 (CDL = 24)
			if control_data_length >= 24 then
				-- Version 1.2, extra bytes if control_data_length is strictly greater
				return "1.2", (control_data_length > 24)
			end
		end

	-- GET_SYSTEM_UNIQUE_ID
	elseif command_type == m.COMMAND_TYPES.GET_SYSTEM_UNIQUE_ID then

		-- Command
		if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND then
			-- Version 1.2 (CDL = 20)
			if control_data_length >= 20 then
				-- Version 1.2, extra bytes if control_data_length is strictly greater
				return "1.2", (control_data_length > 20)
			end

		-- Response
		elseif message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE then
			-- Version 1.2 (CDL = 24)
			if control_data_length >= 24 then
				-- Version 1.2, extra bytes if control_data_length is strictly greater
				return "1.2", (control_data_length > 24)
			end
		end

	-- SET_MEDIA_CLOCK_REFERENCE_INFO
	elseif command_type == m.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO then

		-- Command
		if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND then
			-- Version 1.2 (CDL = 92)
			if control_data_length >= 92 then
				-- Version 1.2, extra bytes if control_data_length is strictly greater
				return "1.2", (control_data_length > 92)
			end

		-- Response
		elseif message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE then
			-- Version 1.2 (CDL = 92)
			if control_data_length >= 92 then
				-- Version 1.2, extra bytes if control_data_length is strictly greater
				return "1.2", (control_data_length > 92)
			end
		end

	-- GET_MEDIA_CLOCK_REFERENCE_INFO
	elseif command_type == m.COMMAND_TYPES.GET_MEDIA_CLOCK_REFERENCE_INFO then

		-- Command
		if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND then
			-- Version 1.2 (CDL = 20)
			if control_data_length >= 20 then
				-- Version 1.2, extra bytes if control_data_length is strictly greater
				return "1.2", (control_data_length > 20)
			end

		-- Response
		elseif message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE then
			-- Version 1.2 (CDL = 92)
			if control_data_length >= 92 then
				-- Version 1.2, extra bytes if control_data_length is strictly greater
				return "1.2", (control_data_length > 92)
			end
		end

	end

end

-- Return the module object
return m
