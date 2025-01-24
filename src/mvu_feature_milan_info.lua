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
	m._fields["mvu.protocol_version"]
	= mFields.CreateField(
		ProtoField.uint32("mvu.protocol_version", "Protocol Version", base.DEC)
	)

	-- Flags for available Milan features
	m._fields["mvu.feature_flags"]
	= mFields.CreateField(
		ProtoField.uint32("mvu.feature_flags", "Feature Flags", base.HEX)
	)

	-- Feature: Redundancy
	m._fields["mvu.feature.redundancy"]
	= mFields.CreateField(
		ProtoField.bool(
			"mvu.feature.redundancy",
			"REDUNDANCY",
			32,          -- parent bitfield size
			nil,         -- table of value strings
			0x00000001)  -- bit mask for this field
	)

	-- Feature: Talker dynamic mappings while running
	m._fields["mvu.feature.talker_dynamic_mappings"]
	= mFields.CreateField(
		ProtoField.bool(
			"mvu.feature.talker_dynamic_mappings",
			"TALKER_DYNAMIC_MAPPINGS_WHILE_RUNNING",
			32,         -- parent bitfield size
			nil,        -- table of value strings
			0x00000002) -- bit mask for this field
	)

	-- Certification version (the version number of the Milan certifications that the PAAD-AE has passed)
	m._fields["mvu.certification_version"]
	= mFields.CreateField(
		ProtoField.string(
			"mvu.certification_version",
			"Certification version",
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
--- @param subtree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @return table<string> errors List of errors encountered
function m.AddFieldsToSubtree(buffer, subtree)

	-- Init list of errors
	local errors = {}

	-- Read IEEE 1722.1 field values
	local message_type        = mIEEE17221Fields.GetMessageType()
	local status_code         = mIEEE17221Fields.GetVendorUniqueStatusCode()
	local control_data_length = mIEEE17221Fields.GetControldataLength()

	-- Read MVU header field values
	local command_type = mHeaders.GetCommandType()

	-- Get the Milan version for this command
	local milan_version = mSpecs.GetMilanVersionOfCommand(message_type, command_type, control_data_length)

	-- If no Milan version was found for this command,
	-- it means that the Control data Length is unexpected
	if milan_version == nil then
		-- Insert error
		errors = mControl.InsertControlDataLengthError(control_data_length, buffer, subtree, errors)
		-- Stop function here
		return errors
	end

	-- If the message is a SUCCESS reponse to a GET_MILAN_INFO command
	if 	message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE
	and status_code == mIEEE17221Specs.VENDOR_UNIQUE_STATUS_CODES.SUCCESS
	and command_type == mSpecs.COMMAND_TYPES.GET_MILAN_INFO
	then

		----------------------------
		-- Add fields to the tree --
		----------------------------

		-- Get MVU payload bytes from buffer
		local mvu_payload_bytes, mvu_payload_start, mvu_payload_length = mHeaders.GetMvuPayload()

		--
		-- Protocol version
		--

		-- Read protocol version (4 bytes)
		local protocol_version = mvu_payload_bytes:int(4, 4)

		-- Write protocol version to the MVU subtree
		subtree:add(m._fields["mvu.protocol_version"], buffer(mvu_payload_start + 4, 4), protocol_version)

		--
		-- Feature flags
		--

		-- Read feature flags
		local feature_flags = mvu_payload_bytes:int(8, 4)

		-- Write feature flags to the MVU subtree
		subtree:add(m._fields["mvu.feature_flags"], buffer(mvu_payload_start + 8, 4), feature_flags)

		-- Write individual features flags to the MVU subtree
		subtree:add(m._fields["mvu.feature.talker_dynamic_mappings"], buffer(mvu_payload_start + 8, 4))
		subtree:add(m._fields["mvu.feature.redundancy"], buffer(mvu_payload_start + 8, 4))

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
			subtree:add(m._fields["mvu.certification_version"], buffer(mvu_payload_start + 12, 4), certification_version)
		end

	end

	-- Return errors
	return errors

end

-- Return module object
return m
