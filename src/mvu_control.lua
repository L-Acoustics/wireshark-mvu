---
--- control.lua
---
--- Functions for logic control
---

-- Require dependency modules
local mSpecs = require("mvu_specs")
local mIEEE17221Specs = require("ieee17221_specs")
local mIEEE17221Fields = require("ieee17221_fields")
local mHelpers = require("mvu_helpers")
local mFields = require("mvu_fields")
local mHeaders = require("mvu_headers")

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

--- The minimum supported version of Wireshark
m._minimum_wireshark_version = "4.2.0"

--------------------
-- Public Methods --
--------------------

--- Determines if the current plugin is compatible with the running version of Wireshark
function m.IsWiresharkVersionCompatible()
	-- Get program version
	local wireshark_version = get_version()
	-- If program version is too old
	local version_comparison = mHelpers.CompareVersions(wireshark_version, m._minimum_wireshark_version)
	if type(version_comparison) ~= "number" or version_comparison < 0 then
		-- Not compatible
		return false
	end
	-- Eventually, the Wireshark version is compatible
	return true
end

--- Read the required minimum version of Wireshark compatible with this plugin
--- @return string
function m.GetMinimumWiresharkVersion()
	return m._minimum_wireshark_version
end

--- Indicate if the current dissected packet is an MVU packet
--- @return boolean is_mvu_packet
function m.IsMvuPacket()

	-- Get IEEE 1722.1 field values
	local control_data_length       = mIEEE17221Fields.GetControldataLength()
	local message_type              = mIEEE17221Fields.GetMessageType()
	local vendor_unique_protocol_id = mIEEE17221Fields.GetVendorUniqueProtocolIdHexString()

	-- It is an MVU packet if:
	-- The Control data Field is valid
	return control_data_length ~= nil
	-- and the Vendor Unique Protocol ID matches MVU
	and vendor_unique_protocol_id == mSpecs.PROTOCOL_ID
	-- and the message type is either a V.U. Command or V.U. Response
	and (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND
	    or message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE)
end

--- Insert an error message of incorrect Control Data Length in the subtree
--- @param control_data_length number|nil The value of the Control Data Length field
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree any The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @param errors table<string> List of existing error messages
--- @return table<string> errors Altered list of error messages
function m.InsertControlDataLengthError(control_data_length, buffer, subtree, errors)

	-- Build eror message
	local error_message = "Unexpected or unsupported Control Data Length (" .. control_data_length .. ") for this command"

	-- Get control data length error expert field from headers
	local f_control_data_length_errors = mFields.GetExpertField("mvu.expert.control_data_length_error")

	-- If expert field was found
	if f_control_data_length_errors ~= nil then
		-- Add control data length error to the subtree
		subtree:add_tvb_expert_info(f_control_data_length_errors, buffer(16, 2), error_message)
	end

	-- Add error
	table.insert(errors, error_message)

	-- Return the updated list of errors
	return errors

end

--- Insert a message in the tree if there are unimplemented extra bytes at the end of the payload
--- @param subtree any The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function m.InsertUnimplementedExtraBytesMessage(subtree)

	-- Read IEEE 1722.1 field values
	local message_type        = mIEEE17221Fields.GetMessageType()
	local control_data_length = mIEEE17221Fields.GetControldataLength()

	-- Read MVU header field values
	local command_type = mHeaders.GetCommandType()

	-- Get the Milan version for this command
	local _, unimplemented_extra_bytes = mSpecs.GetMilanVersionOfCommand(message_type, command_type, control_data_length)

	-- If there are unimplemented extra bytes at the end of the payload
	if unimplemented_extra_bytes == true then
		-- Insert message in the subtree to warn that the message may implement a newer version of Milan specifications
		subtree:add("[Additional bytes at end of payload. This PAAD may implement a newer version of Milan. Consider updating this plugin.]")
	end

end

-- Return module object
return m
