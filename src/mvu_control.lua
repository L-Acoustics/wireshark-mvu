--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Functions for logic control
	---

	Authors: Benjamin Landrot

	Licensed under the GNU General Public License (GPL) version 2
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express of implied.
	See the License for the specific language governing permissions and
	limitations under the License.

]]

-- Stop here if the version of Wireshark is not supported
local mCompatibility = require("mvu_compatibility")
if not mCompatibility.IsWiresharkVersionCompatible() then
	return
end

-- Require dependency modules
local mSpecs = require("mvu_specs")
local mIEEE17221Specs = require("ieee17221_specs")
local mIEEE17221Fields = require("ieee17221_fields")
local mHelpers = require("mvu_helpers")
local mFields = require("mvu_fields")
local mHeaders = require("mvu_headers")

-- Init module object
local m = {}

--------------------
-- Public Methods --
--------------------

--- Indicate if the current dissected packet is an MVU packet
--- @return boolean is_mvu_packet
function m.IsMvuPacket()

	-- Get IEEE 1722.1 field values
	local control_data_length       = mIEEE17221Fields.GetControlDataLength()
	local message_type              = mIEEE17221Fields.GetMessageType()
	local vendor_unique_protocol_id = mIEEE17221Fields.GetVendorUniqueProtocolIdHexString()

	-- It is an MVU packet if:
	-- The Control Data Field is valid
	return control_data_length ~= nil
	-- and the Vendor Unique Protocol ID matches MVU
	and type(vendor_unique_protocol_id) == "string" and vendor_unique_protocol_id:lower() == mSpecs.PROTOCOL_ID:lower()
	-- and the message type is either a V.U. Command or V.U. Response
	and (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND
	    or message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE)
end

--- Insert an error message of incorrect Control Data Length in the subtree
--- @param control_data_length number|nil The value of the Control Data Length field
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree any The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @param errors table<string> List of existing error messages
--- @return table<string> errors Altered list of error messages
function m.InsertControlDataLengthError(control_data_length, buffer, subtree, errors)

	-- Build error message
	local error_message = "Unexpected Control Data Length (" .. control_data_length .. ") for this command"

	-- Get control data length error expert field from headers
	local f_control_data_length_errors = mFields.GetExpertField(mHeaders._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR)

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
--- @param subtree any The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function m.InsertUnimplementedExtraBytesMessage(subtree)

	-- Read IEEE 1722.1 field values
	local message_type        = mIEEE17221Fields.GetMessageType()
	local control_data_length = mIEEE17221Fields.GetControlDataLength()

	-- Read MVU header field values
	local command_type = mHeaders.GetCommandType()

	-- Get the Milan version for this command
	local _, unimplemented_extra_bytes = mSpecs.GetMilanVersionOfCommand(message_type, command_type, control_data_length)

	-- If there are unimplemented extra bytes at the end of the payload
	if unimplemented_extra_bytes == true then
		-- Insert message in the subtree to warn that the message may implement a newer version of Milan specifications
		subtree:add("Additional bytes at end of payload. This PAAD may implement a newer version of Milan. Consider updating this plugin.")
			--- Mark as a generated field (with data inferred but not contained in the packet)
			:set_generated(true)
	end

end

-- Return module object
return m
