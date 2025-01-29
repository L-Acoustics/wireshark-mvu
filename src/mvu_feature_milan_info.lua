---
--- mvu_feature_milan_info.lua
---
--- Handle fields related to GET_MILAN_INFO commands
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

-- List of fields related to GET_MILAN_INFO commands/responses
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_NAMES = {
    PROTOCOL_VERSION                = "mvu.protocol_version",
    FEATURE_FLAGS                   = "mvu.feature_flags",
    FEATURE_REDUNDANCY              = "mvu.feature.redundancy",
    FEATURE_TALKER_DYNAMIC_MAPPINGS = "mvu.feature.talker_dynamic_mappings",
    PAAD_CERTIFICATION_VERSION      = "mvu.paad_certification_version",
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

	-- Protocol version
	--   Expected in:
	--     GET_MILAN_INFO command
	--     GET_MILAN_INFO response
	--     GET_SYSTEM_UNIQUE_ID command
	m._fields[m._FIELD_NAMES.PROTOCOL_VERSION]
	= mFields.CreateField(
		ProtoField.uint32(m._FIELD_NAMES.PROTOCOL_VERSION, "Protocol Version", base.DEC)
	)

	-- Flags for available Milan features
	--   Expected in:
	--     GET_MILAN_INFO response
	m._fields[m._FIELD_NAMES.FEATURE_FLAGS]
	= mFields.CreateField(
		ProtoField.uint32(m._FIELD_NAMES.FEATURE_FLAGS, "Feature Flags", base.HEX)
	)

	-- Feature: Redundancy
	--   Expected in:
	--     GET_MILAN_INFO response
	m._fields[m._FIELD_NAMES.FEATURE_REDUNDANCY]
	= mFields.CreateField(
		ProtoField.bool(
			m._FIELD_NAMES.FEATURE_REDUNDANCY,
			"REDUNDANCY",
			32,          -- parent bitfield size
			nil,         -- table of value strings
			0x00000001)  -- bit mask for this field
	)

	-- Feature: Talker dynamic mappings while running
	--   Expected in:
	--     GET_MILAN_INFO response
	m._fields[m._FIELD_NAMES.FEATURE_TALKER_DYNAMIC_MAPPINGS]
	= mFields.CreateField(
		ProtoField.bool(
			m._FIELD_NAMES.FEATURE_TALKER_DYNAMIC_MAPPINGS,
			"TALKER_DYNAMIC_MAPPINGS_WHILE_RUNNING",
			32,         -- parent bitfield size
			nil,        -- table of value strings
			0x00000002) -- bit mask for this field
	)

	-- Certification version (the version number of the Milan certifications that the PAAD-AE has passed)
	--   Expected in:
	--     GET_MILAN_INFO response
	m._fields[m._FIELD_NAMES.PAAD_CERTIFICATION_VERSION]
	= mFields.CreateField(
		ProtoField.string(
			m._FIELD_NAMES.PAAD_CERTIFICATION_VERSION,
			"PAAD certification version",
			base.ASCII,
			"The version number of the Milan certifications that the PAAD-AE has passed"
		)
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
--- @return table<string> errors Amended list of errors
--- @return boolean|nil blocking_errors Indicates if one of the returned errors is blocking and should interrupt further packet analysis
function m.AddFieldsToSubtree(buffer, subtree, errors)

	-- Read IEEE 1722.1 field values
	local message_type        = mIEEE17221Fields.GetMessageType()
	local status_code         = mIEEE17221Fields.GetVendorUniqueStatusCode()
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
		-- Stop function here
		return errors, true
	end

	-- If the message is a SUCCESS response to a GET_MILAN_INFO command
	if 	message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE
	and status_code == mIEEE17221Specs.VENDOR_UNIQUE_STATUS_CODES.SUCCESS
	and command_type == mSpecs.COMMAND_TYPES.GET_MILAN_INFO
	then

		----------------------------
		-- Add fields to the tree --
		----------------------------

		-- Get MVU payload bytes from buffer
		local mvu_payload_bytes, mvu_payload_start = mHeaders.GetMvuPayload()

		--
		-- Protocol version
		--

		-- Read protocol version (4 bytes)
		local protocol_version = mvu_payload_bytes:int(4, 4)

		-- Write protocol version to the MVU subtree
		subtree:add(m._fields[m._FIELD_NAMES.PROTOCOL_VERSION], buffer(mvu_payload_start + 4, 4), protocol_version)

		--
		-- Feature flags
		--

		-- Read feature flags
		local feature_flags = mvu_payload_bytes:int(8, 4)

		-- Write feature flags to the MVU subtree
		subtree:add(m._fields[m._FIELD_NAMES.FEATURE_FLAGS], buffer(mvu_payload_start + 8, 4), feature_flags)

		-- Write individual features flags to the MVU subtree
		subtree:add(m._fields[m._FIELD_NAMES.FEATURE_TALKER_DYNAMIC_MAPPINGS], buffer(mvu_payload_start + 8, 4))
		subtree:add(m._fields[m._FIELD_NAMES.FEATURE_REDUNDANCY], buffer(mvu_payload_start + 8, 4))

		--
		-- Certification version
		--

		-- Read certification version numbers
		local certification_version_numbers = { string.unpack("bbbb", mvu_payload_bytes:raw(12, 4)) }

		-- If certification numbers are not zeros
		if certification_version_numbers[1] > 0 then
			-- Build string version
			local certification_version = string.format("%d.%d", certification_version_numbers[1], certification_version_numbers[2])
			-- Write certification version
			subtree:add(m._fields[m._FIELD_NAMES.PAAD_CERTIFICATION_VERSION], buffer(mvu_payload_start + 12, 4), certification_version)
		end

	end

	-- Return non-blocking errors
	return errors

end

-- Return module object
return m
