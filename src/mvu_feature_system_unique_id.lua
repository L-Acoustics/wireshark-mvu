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
	local message_type = mIEEE17221Fields.GetMessageType()

	-- Read MVU header field values
	local command_type = mHeaders.GetCommandType()

	-- if the message is a SET_SYSTEM_UNIQUE_ID command or a GET_SYSTEM_UNIQUE_ID response
	if (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND and command_type == mSpecs.COMMAND_TYPES.SET_SYSTEM_UNIQUE_ID)
	or (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and command_type == mSpecs.COMMAND_TYPES.GET_SYSTEM_UNIQUE_ID)
	then

		-- Read Control data Length
		local control_data_length = mIEEE17221Fields.GetControldataLength()

		-- If the control data length is smaller than expected
		local expected_control_data_length = 24
		if control_data_length < expected_control_data_length then

			-- Build eror message
			local error_message = "Control Data Length value is too small for this command"
				.. " (CDL = " .. control_data_length
				.. ", expected: " .. expected_control_data_length .. ")"

			-- Get control data length error expert field from headers
			local f_control_data_length_errors = mFields.GetExpertField("mvu.expert.control_data_length_error")

			-- If expert field was found
			if f_control_data_length_errors ~= nil then
				-- Add control data length error to the subtree
				subtree:add_tvb_expert_info(f_control_data_length_errors, buffer(16, 2), error_message)
			end

			-- Add error
			table.insert(errors, error_message)

			-- Do no more dissecting, stop function here
			return errors

		end

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
