--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Handle fields related to GET_SYSTEM_UNIQUE_ID/SET_SYSTEM_UNIQUE_ID
		commands/responses
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

-- Require dependency modules
local mFields = require("mvu_fields")
local mSpecs = require("mvu_specs")
local mHeaders = require("mvu_headers")
local mIEEE17221Specs = require("ieee17221_specs")
local mIEEE17221Fields = require("ieee17221_fields")
local mControl = require("mvu_control")
local mHelpers = require("helpers")

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

-- List of fields related to GET_SYSTEM_UNIQUE_ID/SET_SYSTEM_UNIQUE_ID commands/responses
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_NAMES = {
    SYSTEM_UNIQUE_ID        = "mvu.system_unique_id",
    SYSTEM_UNIQUE_ID_NAME   = "mvu.system_unique_id_name",
}

-- Table of offset position and bytes size in the MVU payload for each valid combination of field/message type
m._fields_payload_offset = {
	[m._FIELD_NAMES.SYSTEM_UNIQUE_ID] = {
		[mSpecs.COMMAND_TYPES.SET_SYSTEM_UNIQUE_ID] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND ] = 4,
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 4,
		},
		[mSpecs.COMMAND_TYPES.GET_SYSTEM_UNIQUE_ID] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 4,
		},
	},
	[m._FIELD_NAMES.SYSTEM_UNIQUE_ID_NAME] = {
		[mSpecs.COMMAND_TYPES.SET_SYSTEM_UNIQUE_ID] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND ] = 12,
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 12,
		},
		[mSpecs.COMMAND_TYPES.GET_SYSTEM_UNIQUE_ID] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 12,
		},
	},
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

	-- System unique ID number
	--   Expected in:
	--     GET_SYSTEM_UNIQUE_ID response
	--     SET_SYSTEM_UNIQUE_ID command
	--     SET_SYSTEM_UNIQUE_ID response
	m._fields[m._FIELD_NAMES.SYSTEM_UNIQUE_ID]
	= mFields.CreateField(
		ProtoField.uint64(m._FIELD_NAMES.SYSTEM_UNIQUE_ID, "System Unique ID", base.HEX)
	)

	-- System unique ID name
	--   Expected in:
	--     GET_SYSTEM_UNIQUE_ID response
	--     SET_SYSTEM_UNIQUE_ID command
	--     SET_SYSTEM_UNIQUE_ID response
	m._fields[m._FIELD_NAMES.SYSTEM_UNIQUE_ID_NAME]
	= mFields.CreateField(
		ProtoField.string(
			m._FIELD_NAMES.SYSTEM_UNIQUE_ID_NAME,
			"System Unique ID Name",
			base.ASCII,
			"Name part of the network-wide unique identifier"
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
--- @param existing_errors table<string>|nil Existing errors
--- @param existing_warnings table<string>|nil List of string warnings found during dissecting so far
--- @return table<string> errors List of errors encountered
--- @return boolean|nil blocking_errors Indicates if one of the returned errors is blocking and should interrupt further packet analysis
--- @return table<string>|nil warnings
function m.AddFieldsToSubtree(buffer, subtree, existing_errors, existing_warnings)

	local errors = existing_errors or {}

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
		return errors, true, existing_warnings
	end

	-- Get MVU payload bytes from buffer
	local _, mvu_payload_start = mHeaders.GetMvuPayload()

	--- Function to add a field to the Tree
	--- @param field any The protocol field object
	--- @param size number The byte size of the field's data
	--- @param execute_on_range function|nil An optional function executed on the TVB range for this field
	--- @param custom_value_function function|nil An optional function for customizing the displayed value for the field
	--- @param do_not_add_on_nil_custom_value boolean|nil An optional flag to determine if the field should be added to the tree when the custom value function returns nil
	local add_field_to_tree = function(field, size, execute_on_range, custom_value_function, do_not_add_on_nil_custom_value)
		-- if the field has an offset position for the command and message types
		if  m._fields_payload_offset[field] ~= nil
		and m._fields_payload_offset[field][command_type] ~= nil
		and m._fields_payload_offset[field][command_type][message_type] ~= nil
		then
			-- Read payload offset position for this field
			local payload_offset = m._fields_payload_offset[field][command_type][message_type]

			-- If a custom function is provided
			if (type(custom_value_function) == "function") then
				-- Execute custom function
				local custom_value = custom_value_function(buffer(mvu_payload_start + payload_offset, size))
				-- If the custom value is not nil or the field can be added in case of nil custom value
				if not (custom_value == nil and do_not_add_on_nil_custom_value) then
					-- Write field to the MVU subtree with custom display value
					subtree:add(m._fields[field], buffer(mvu_payload_start + payload_offset, size), custom_value)
				end
			else
				-- Write field to the MVU subtree
				subtree:add(m._fields[field], buffer(mvu_payload_start + payload_offset, size))
			end
			-- If any, execute provided function on buffer range
			if (type(execute_on_range) == "function") then
				execute_on_range(buffer(mvu_payload_start + payload_offset, size))
			end
		end
	end

	-- Add all fields to the tree
	-- Version 1.2
	if (mHelpers.CompareVersions(milan_version, "1.2") >= 0) then
		add_field_to_tree(m._FIELD_NAMES.SYSTEM_UNIQUE_ID, 8)
	end
	-- Version 1.3
	if (mHelpers.CompareVersions(milan_version, "1.3") >= 0) then
		add_field_to_tree(m._FIELD_NAMES.SYSTEM_UNIQUE_ID_NAME, 64)
	end

	-- Return non-blocking errors
	return errors, false, existing_warnings

end

-- Return module object
return m
