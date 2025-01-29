---
--- mvu_feature_clock_reference_info.lua
---
--- Handle fields related to GET_CLOCK_REFERENCE_INFO/SET_CLOCK_REFERENCE_INFO commands/responses
---

-- Require dependency modules
local mFields = require("mvu_fields")
local mSpecs = require("mvu_specs")
local mHeaders = require("mvu_headers")
local mIEEE17221Specs = require("ieee17221_specs")
local mIEEE17221Fields = require("ieee17221_fields")
local mControl = require("mvu_control")

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

-- List of fields related to GET_CLOCK_REFERENCE_INFO/SET_CLOCK_REFERENCE_INFO commands/responses
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_NAMES = {
    CLOCK_DOMAIN_INDEX                   = "mvu.clock_domain_index",
    MEDIA_CLOCK_FLAGS                    = "mvu.media_clock_flags",
    MEDIA_CLOCK_REFERENCE_PRIORITY_VALID = "mvu.media_clock.reference_priority_valid",
    MEDIA_CLOCK_DOMAIN_NAME_VALID        = "mvu.media_clock.domain_name_valid",
    DEFAULT_MCR_PRIORITY                 = "mvu.default_mcr_priority",
    USER_MCR_PRIORITY                    = "mvu.user_mcr_priority",
    MEDIA_CLOCK_DOMAIN_NAME              = "mvu.media_clock.domain_name",
}

--------------------
-- Public Methods --
--------------------

--- Declare all fields of this feature
function m.DeclareFields()

	------------
	-- FIELDS --
	------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField

	-- Clock domain index
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO command
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields[m._FIELD_NAMES.CLOCK_DOMAIN_INDEX]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.CLOCK_DOMAIN_INDEX, "Clock Domain Index", base.DEC)
	)

	-- Flags for Media Clock fields validity
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields[m._FIELD_NAMES.MEDIA_CLOCK_FLAGS]
	= mFields.CreateField(
		ProtoField.uint32(m._FIELD_NAMES.MEDIA_CLOCK_FLAGS, "Media Clock Flags", base.HEX)
	)

	-- Media clock reference priority field validity
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields[m._FIELD_NAMES.MEDIA_CLOCK_REFERENCE_PRIORITY_VALID]
	= mFields.CreateField(
		ProtoField.bool(
			m._FIELD_NAMES.MEDIA_CLOCK_REFERENCE_PRIORITY_VALID,
			"REFERENCE PRIORITY VALID",
			8,    -- parent bitfield size
			nil,  -- table of value strings
			0x01) -- bit mask for this field
	)

	-- Media clock domain name field validity
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields[m._FIELD_NAMES.MEDIA_CLOCK_DOMAIN_NAME_VALID]
	= mFields.CreateField(
		ProtoField.bool(
			m._FIELD_NAMES.MEDIA_CLOCK_DOMAIN_NAME_VALID,
			"DOMAIN NAME VALID",
			8,    -- parent bitfield size
			nil,  -- table of value strings
			0x02) -- bit mask for this field
	)

	-- Default media clock reference priority
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields[m._FIELD_NAMES.DEFAULT_MCR_PRIORITY]
	= mFields.CreateField(
		ProtoField.uint8(m._FIELD_NAMES.DEFAULT_MCR_PRIORITY, "Default Media Clock Reference Priority", base.DEC)
	)

	-- User media clock reference priority
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields[m._FIELD_NAMES.USER_MCR_PRIORITY]
	= mFields.CreateField(
		ProtoField.uint8(m._FIELD_NAMES.USER_MCR_PRIORITY, "User Media Clock Reference Priority", base.DEC)
	)

	-- Media clock domain name
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields[m._FIELD_NAMES.MEDIA_CLOCK_DOMAIN_NAME]
	= mFields.CreateField(
		ProtoField.string(m._FIELD_NAMES.MEDIA_CLOCK_DOMAIN_NAME, "Media Clock Domain Name", base.UNICODE)
	)

	-------------------
	-- EXPERT FIELDS --
	-------------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoExpert

end

--- Add fields to the subtree
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @param errors table<string> Existing errors
--- @return table<string> errors List of errors encountered
--- @return boolean|nil blocking_errors Indicates if one of the returned errors is blocking and should interrupt further packet analysis
function m.AddFieldsToSubtree(buffer, subtree, errors)

	-- Read IEEE 1722.1 field values
	local message_type        = mIEEE17221Fields.GetMessageType()
	local control_data_length = mIEEE17221Fields.GetControlDataLength()

	-- Read MVU header field values
	local command_type = mHeaders.GetCommandType()

	-- Get the Milan version for this command
	local milan_version = mSpecs.GetMilanVersionOfCommand(message_type, command_type, control_data_length)

	-- If no Milan version was found for this command,
	-- it means that the Control Data Length is unexpected
	if milan_version == nil then
		-- Insert error
		errors = mControl.InsertControlDataLengthError(control_data_length, buffer, subtree, errors)
		-- Return blocking error
		return errors, true
	end

	-- Get MVU payload bytes from buffer
	local mvu_payload_bytes, mvu_payload_start = mHeaders.GetMvuPayload()

	-- If the message is one of these:
	--   GET_MEDIA_CLOCK_REFERENCE_INFO command
	--   SET_MEDIA_CLOCK_REFERENCE_INFO command
	if command_type == mSpecs.COMMAND_TYPES.GET_MEDIA_CLOCK_REFERENCE_INFO
	or command_type == mSpecs.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO
	then

		----------------------------
		-- Add fields to the tree --
		----------------------------

		--
		-- Clock domain index
		--

		-- Get clock domain index
		local clock_domain_index = mvu_payload_bytes:int(2, 2)

		-- Write clock domain index to the MVU subtree
		subtree:add(m._fields["mvu.clock_domain_index"], buffer(mvu_payload_start + 2, 2), clock_domain_index)

	end

	-- If the message is one of these:
	--   SET_MEDIA_CLOCK_REFERENCE_INFO command
	--   SET_MEDIA_CLOCK_REFERENCE_INFO response
	--   GET_MEDIA_CLOCK_REFERENCE_INFO response
	if (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND and command_type == mSpecs.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO)
	or (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and
		(command_type == mSpecs.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO or command_type == mSpecs.COMMAND_TYPES.GET_MEDIA_CLOCK_REFERENCE_INFO))
	then

		----------------------------
		-- Add fields to the tree --
		----------------------------

		--
		-- Media clock reference info flags
		--

		-- Get media clock reference info flags
		local media_clock_reference_info_flags = mvu_payload_bytes:int(4, 1)

		-- Write media clock reference info flags to the MVU subtree
		subtree:add(m._fields["mvu.media_clock_flags"], buffer(mvu_payload_start + 4, 1), media_clock_reference_info_flags)

		-- Write individual media clock reference info flags to the MVU subtree
		subtree:add(m._fields[m._FIELD_NAMES.MEDIA_CLOCK_REFERENCE_PRIORITY_VALID], buffer(mvu_payload_start + 4, 1))
		subtree:add(m._fields[m._FIELD_NAMES.MEDIA_CLOCK_DOMAIN_NAME_VALID], buffer(mvu_payload_start + 4, 1))

		--
		-- Default media clock reference priority
		--

		-- Get default media clock reference priority
		local default_media_clock_reference_priority = mvu_payload_bytes:uint(6, 1)

		-- Write default media clock reference priority to the MVY subtree
		subtree:add(m._fields[m._FIELD_NAMES.DEFAULT_MCR_PRIORITY], buffer(mvu_payload_start + 6, 1), default_media_clock_reference_priority)

		--
		-- User media clock reference priority
		--

		-- Get user media clock reference priority
		local user_media_clock_reference_priority = mvu_payload_bytes:uint(7, 1)

		-- Write user media clock reference priority to the MVY subtree
		subtree:add(m._fields[m._FIELD_NAMES.USER_MCR_PRIORITY], buffer(mvu_payload_start + 7, 1), user_media_clock_reference_priority)

		--
		-- Media clock domain name
		--

		-- Get media clock domain name
		local media_clock_domain_name = buffer(mvu_payload_start + 12, 64):raw()

		-- Determine media clock domain name string length
		local null_character_position = media_clock_domain_name:find("\0")
		local media_clock_domain_name_length = null_character_position ~= nil and (null_character_position - 1) or 64

		-- Write media clock domain name to the MVU subtree
		subtree:add(m._fields[m._FIELD_NAMES.MEDIA_CLOCK_DOMAIN_NAME], buffer(mvu_payload_start + 12, media_clock_domain_name_length), media_clock_domain_name)

	end

	-- Return non-blocking errors
	return errors

end

-- Return module object
return m
