--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Handle fields related to GET_STREAM_INPUT_INFO_EX commands
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
local mIEEE8021QatSpecs = require("ieee8021Qat_specs")
local mControl = require("mvu_control")
local mHelpers = require("helpers")
local mAvnuSpecs = require("avnu_specs")

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

-- List of fields related to BIND_STREAM commands/responses
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_NAMES = {
	DESCRIPTOR_TYPE             = "mvu.descriptor_type",
	DESCRIPTOR_INDEX            = "mvu.descriptor_index",
	TALKER_ENTITY_ID            = "mvu.stream.talker_entity_id",
	TALKER_STREAM_ID            = "mvu.stream.talker_stream_id",
	PROBING_STATUS              = "mvu.stream.probing_status",
	ACMP_STATUS                 = "mvu.stream.acmp_status",
	DESCRIPTOR_TYPE_ERROR       = "mvu.expert.descriptor_type_error",
}

-- Table of offset position and bytes size in the MVU payload for each valid combination of field/command type/message type
m._fields_payload_offset = {
	[m._FIELD_NAMES.DESCRIPTOR_TYPE] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND ] = 4,
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 4,
		}
	},
	[m._FIELD_NAMES.DESCRIPTOR_INDEX] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND ] = 6,
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 6,
		}
	},
	[m._FIELD_NAMES.TALKER_ENTITY_ID] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 8,
		},
	},
	[m._FIELD_NAMES.TALKER_STREAM_ID] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 16,
		},
	},
	[m._FIELD_NAMES.PROBING_STATUS] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 18,
		},
	},
	[m._FIELD_NAMES.ACMP_STATUS] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 18,
		},
	}
}

-- Internal list of expert fields
m._experts = {}

--------------------
-- Public Methods --
--------------------

--- Declare all fields of this feature
function m.DeclareFields()

	------------
	-- FIELDS --
	------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField

	-- Descriptor Type
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX command
	--     GET_STREAM_INPUT_INFO_EX response
	local descriptor_type_valuestring = mHelpers.GetTableValuesWithNumberKey(mIEEE17221Specs.DESCRIPTOR_TYPES)
	m._fields[m._FIELD_NAMES.DESCRIPTOR_TYPE]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.DESCRIPTOR_TYPE, "Descriptor Type", base.HEX, descriptor_type_valuestring)
	)

	-- Descriptor Index
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX command
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.DESCRIPTOR_INDEX]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.DESCRIPTOR_INDEX, "Descriptor Index", base.DEC)
	)

	-- Talker Entity ID
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.TALKER_ENTITY_ID]
	= mFields.CreateField(
		ProtoField.uint64(m._FIELD_NAMES.TALKER_ENTITY_ID, "Talker Entity ID", base.HEX)
	)

	-- Talker Stream ID
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.TALKER_STREAM_ID]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.TALKER_STREAM_ID, "Talker Stream ID", base.DEC)
	)

	-- Probing status
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	local probing_status_valuestring = mHelpers.GetTableValuesWithNumberKey(mSpecs.PROBING_STATUS)
	m._fields[m._FIELD_NAMES.PROBING_STATUS]
	= mFields.CreateField(
		ProtoField.uint8(m._FIELD_NAMES.PROBING_STATUS, "Probing Status", base.DEC, probing_status_valuestring)
	)

	-- ACMP status
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	local acmp_status_valuestring = mHelpers.GetTableValuesWithNumberKey(mIEEE17221Specs.ACMP_FAILURE_CODES)
	m._fields[m._FIELD_NAMES.ACMP_STATUS]
	= mFields.CreateField(
		ProtoField.uint8(m._FIELD_NAMES.ACMP_STATUS, "ACMP Failure Code", base.DEC, acmp_status_valuestring)
	)

	-------------------
	-- EXPERT FIELDS --
	-------------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoExpert

	-- Descriptor Type error
	local descriptor_type_error = ProtoExpert.new(m._FIELD_NAMES.DESCRIPTOR_TYPE_ERROR, "Descriptor Type error", expert.group.PROTOCOL, expert.severity.ERROR)
	m._experts[m._FIELD_NAMES.DESCRIPTOR_TYPE_ERROR] = mFields.CreateExpertField(m._FIELD_NAMES.DESCRIPTOR_TYPE_ERROR, descriptor_type_error)

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
	--local status_code         = mIEEE17221Fields.GetVendorUniqueStatusCode()
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

	----------------------------
	-- Add fields to the tree --
	----------------------------

	-- Get MVU payload bytes from buffer
	local _, mvu_payload_start = mHeaders.GetMvuPayload()

	--- Function to add a field to the Tree
	--- @param field any The protocol field object
	--- @param size number The byte size of the field's data
	--- @param execute_on_range function|nil An optional function executed on the TVB range for this field
	--- @param value_calculator function|nil An optional function to calculate the field's value from the TVB range
	local add_field_to_tree = function(field, size, execute_on_range, value_calculator)
		-- if the field has an offset position for the command and message types
		if  m._fields_payload_offset[field] ~= nil
		and m._fields_payload_offset[field][command_type] ~= nil
		and m._fields_payload_offset[field][command_type][message_type] ~= nil
		then
			-- Read payload offset position for this field
			local payload_offset = m._fields_payload_offset[field][command_type][message_type]

			-- If a function is provided, calculate the field's valud
			if (type(value_calculator) == "function") then
				local field_value = value_calculator(buffer(mvu_payload_start + payload_offset, size))
				subtree:add(m._fields[field], buffer(mvu_payload_start + payload_offset, size), field_value)
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

	-- Init variables needed for errors
	local descriptor_type = nil

	-- Add all fields
	add_field_to_tree(m._FIELD_NAMES.DESCRIPTOR_TYPE            , 2, function(range) descriptor_type = range:int() end, nil)
	add_field_to_tree(m._FIELD_NAMES.DESCRIPTOR_INDEX           , 2, nil, nil)
	add_field_to_tree(m._FIELD_NAMES.TALKER_ENTITY_ID           , 8, nil, nil)
	add_field_to_tree(m._FIELD_NAMES.TALKER_STREAM_ID           , 2, nil, nil)
	add_field_to_tree(m._FIELD_NAMES.PROBING_STATUS             , 1, nil, function(range) return bit.rshift(range:uint(), 5) end)
	add_field_to_tree(m._FIELD_NAMES.ACMP_STATUS                , 1, nil, function(range) return range:int() & 0x1f end)

	------------------
	-- Check errors --
	------------------

	local errors = {}

	--
	-- Descriptor Type error
	--

	-- If the command is GET_STREAM_INPUT_INFO_EX but the Descriptor Type is not STREAM_INPUT (0x0005)
	if command_type == mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX
	and descriptor_type ~= mIEEE17221Specs.DESCRIPTOR_TYPES.STREAM_INPUT
	then

		-- Build error message
		local error_message = "The Descriptor Type shall be set to STREAM_INPUT (0x0005)"

		-- Add control data length error to the subtree
		subtree:add_tvb_expert_info(m._experts[m._FIELD_NAMES.DESCRIPTOR_TYPE_ERROR], buffer(mvu_payload_start + 4, 2), error_message)

		-- Add error message to errors list
		table.insert(errors, error_message)

		-- Return blocking error
		return errors, true

	end

	-- Return non-blocking errors
	return errors

end

-- Return module object
return m
