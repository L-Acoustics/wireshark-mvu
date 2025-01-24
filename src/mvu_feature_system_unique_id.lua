---
--- mvu_feature_system_unique_id.lua
---
--- Handle fields related to GET_SYSTEM_UNIQUE_ID/SET_SYSTEM_UNIQUE_ID commands/responses
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

	-- System unique ID
	m._fields["mvu.system_unique_id"]
	= mFields.CreateField(
		ProtoField.uint32 ("mvu.system_unique_id", "System Unique ID", base.HEX)
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

	-- if the message is a SET_SYSTEM_UNIQUE_ID command or a GET_SYSTEM_UNIQUE_ID response
	if (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND and command_type == mSpecs.COMMAND_TYPES.SET_SYSTEM_UNIQUE_ID)
	or (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and command_type == mSpecs.COMMAND_TYPES.GET_SYSTEM_UNIQUE_ID)
	then

		----------------------------
		-- Add fields to the tree --
		----------------------------

		-- Get MVU payload bytes from buffer
		local mvu_payload_bytes, mvu_payload_start = mHeaders.GetMvuPayload()

		-- Get system unique id
		local system_unique_id = mvu_payload_bytes:int(4, 4)

		-- Write system unique ID to the MVU subtree
		subtree:add(m._fields["mvu.system_unique_id"], buffer(mvu_payload_start + 4, 4), system_unique_id)
	end

	-- Return errors
	return errors

end

-- Return module object
return m
