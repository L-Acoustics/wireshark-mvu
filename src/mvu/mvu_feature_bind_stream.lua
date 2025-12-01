--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Handle fields related to BIND_STREAM commands
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

-- List of fields related to BIND_STREAM commands/responses
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_NAMES = {
	STREAM_FLAGS                = "mvu.stream.flags",
	STREAM_FLAGS_STREAMING_WAIT = "mvu.stream.flags.streaming_waiting",
	DESCRIPTOR_TYPE             = "mvu.descriptor_type",
	DESCRIPTOR_INDEX            = "mvu.descriptor_index",
	TALKER_ENTITY_ID            = "mvu.stream.talker_entity_id",
	TALKER_STREAM_INDEX         = "mvu.stream.talker_stream_index",
	DESCRIPTOR_TYPE_ERROR       = "mvu.expert.descriptor_type_error",
	RESPONSE_REPLICATES_ERROR   = "mvu.expert.response_replicates_command_values_error",
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

	-- Stream Flags
	--   Expected in:
	--     BIND_STREAM command
	--     BIND_STREAM response
	m._fields[m._FIELD_NAMES.STREAM_FLAGS]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.STREAM_FLAGS, "Stream Flags", base.HEX)
	)

	-- Stream Flag: STREAMING_WAIT
	--   Expected in:
	--     BIND_STREAM command
	--     BIND_STREAM response
	m._fields[m._FIELD_NAMES.STREAM_FLAGS_STREAMING_WAIT]
	= mFields.CreateField(
		ProtoField.bool(
			m._FIELD_NAMES.STREAM_FLAGS_STREAMING_WAIT,
			mSpecs.BIND_STREAM_FLAGS[0x00000001],
			16,          -- parent bitfield size
			nil,         -- table of value strings
			0x00000001)  -- bit mask for this field
	)

	-- Descriptor Type
	--   Expected in:
	--     BIND_STREAM command
	--     BIND_STREAM response
	--     UNBIND_STREAM command
	--     UNBIND_STREAM response
	local descriptor_type_valuestring = mHelpers.GetTableValuesWithNumberKey(mIEEE17221Specs.DESCRIPTOR_TYPES)
	m._fields[m._FIELD_NAMES.DESCRIPTOR_TYPE]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.DESCRIPTOR_TYPE, "Descriptor Type", base.HEX, descriptor_type_valuestring)
	)

	-- Descriptor Index
	--   Expected in:
	--     BIND_STREAM command
	--     BIND_STREAM response
	--     UNBIND_STREAM command
	--     UNBIND_STREAM response
	m._fields[m._FIELD_NAMES.DESCRIPTOR_INDEX]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.DESCRIPTOR_INDEX, "Descriptor Index", base.DEC)
	)

	-- Talker Entity ID
	--   Expected in:
	--     BIND_STREAM command
	--     BIND_STREAM response
	--     UNBIND_STREAM command
	--     UNBIND_STREAM response
	m._fields[m._FIELD_NAMES.TALKER_ENTITY_ID]
	= mFields.CreateField(
		ProtoField.uint64(m._FIELD_NAMES.TALKER_ENTITY_ID, "Talker Entity ID", base.HEX)
	)

	-- Talker Stream Index
	--   Expected in:
	--     BIND_STREAM command
	--     BIND_STREAM response
	--     UNBIND_STREAM command
	--     UNBIND_STREAM response
	m._fields[m._FIELD_NAMES.TALKER_STREAM_INDEX]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.TALKER_STREAM_INDEX, "Talker Stream Index", base.DEC)
	)

	-------------------
	-- EXPERT FIELDS --
	-------------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoExpert

	-- Descriptor Type error
	local descriptor_type_error = ProtoExpert.new(m._FIELD_NAMES.DESCRIPTOR_TYPE_ERROR, "Descriptor Type error", expert.group.PROTOCOL, expert.severity.ERROR)
	m._experts[m._FIELD_NAMES.DESCRIPTOR_TYPE_ERROR] = mFields.CreateExpertField(m._FIELD_NAMES.DESCRIPTOR_TYPE_ERROR, descriptor_type_error)

	-- Response replicates Command values error
	local response_replicates_command_values_error = ProtoExpert.new(m._FIELD_NAMES.RESPONSE_REPLICATES_ERROR, "Response replicates Command values error", expert.group.PROTOCOL, expert.severity.ERROR)
	m._experts[m._FIELD_NAMES.RESPONSE_REPLICATES_ERROR] = mFields.CreateExpertField(m._FIELD_NAMES.RESPONSE_REPLICATES_ERROR, response_replicates_command_values_error)

end

--- Add fields to the subtree
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @param existing_errors table<string>|nil List of string errors found during dissecting so far
--- @param existing_warnings table<string>|nil List of string warnings found during dissecting so far
--- @return table<string> errors Amended list of errors
--- @return boolean|nil blocking_errors Indicates if one of the returned errors is blocking and should interrupt further packet analysis
--- @return table<string>|nil warnings
function m.AddFieldsToSubtree(buffer, subtree, existing_errors, existing_warnings)

	local errors = existing_errors or {}

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
		return errors, true, existing_warnings
	end

	-- If the message is BIND_STREAM or UNBIND_STREAM
	if command_type == mSpecs.COMMAND_TYPES.BIND_STREAM
	or command_type == mSpecs.COMMAND_TYPES.UNBIND_STREAM
	then

		----------------------------
		-- Add fields to the tree --
		----------------------------

		-- Init field value variables
		local stream_flags, descriptor_type, descriptor_index, talker_entity_id, talker_stream_index

		-- Get MVU payload bytes from buffer
		local mvu_payload_bytes, mvu_payload_start = mHeaders.GetMvuPayload()

		--
		-- Stream flags (BIND_STREAM only)
		--
		if command_type == mSpecs.COMMAND_TYPES.BIND_STREAM then

			-- Read stream flags
			stream_flags = mvu_payload_bytes:int(2, 2)

			-- Write stream flags to the MVU subtree
			subtree:add(m._fields[m._FIELD_NAMES.STREAM_FLAGS], buffer(mvu_payload_start + 2, 2), stream_flags)

			-- Write individual stream flags to the MVU subtree
			subtree:add(m._fields[m._FIELD_NAMES.STREAM_FLAGS_STREAMING_WAIT], buffer(mvu_payload_start + 2, 2))

		end

		--
		-- Descriptor Type
		--

		-- Read descriptor type
		descriptor_type = mvu_payload_bytes:int(4, 2)

		-- Write descriptor type to the MVU subtree
		subtree:add(m._fields[m._FIELD_NAMES.DESCRIPTOR_TYPE], buffer(mvu_payload_start + 4, 2), descriptor_type)

		--
		-- Descriptor Index
		--

		-- Read descriptor index
		descriptor_index = mvu_payload_bytes:int(6, 2)

		-- Write descriptor type to the MVU subtree
		subtree:add(m._fields[m._FIELD_NAMES.DESCRIPTOR_INDEX], buffer(mvu_payload_start + 6, 2), descriptor_index)

		--
		-- Talker Entity ID (BIND_STREAM only)
		--
		if command_type == mSpecs.COMMAND_TYPES.BIND_STREAM then

			-- Read field value
			talker_entity_id = mvu_payload_bytes:uint64(8, 8)

			-- Write field to the MVU subtree
			subtree:add(m._fields[m._FIELD_NAMES.TALKER_ENTITY_ID], buffer(mvu_payload_start + 8, 8), talker_entity_id)

		end

		--
		-- Talker Stream ID (BIND_STREAM only)
		--
		if command_type == mSpecs.COMMAND_TYPES.BIND_STREAM then

			-- Read field value
			talker_stream_index = mvu_payload_bytes:int(16, 2)

			-- Write field to the MVU subtree
			subtree:add(m._fields[m._FIELD_NAMES.TALKER_STREAM_INDEX], buffer(mvu_payload_start + 16, 2), talker_stream_index)

		end

		------------------
		-- Check errors --
		------------------

		local errors = {}

		--
		-- Descriptor Type error
		--

		-- If the Descriptor Type is not STREAM_INPUT (0x0005)
		if descriptor_type ~= mIEEE17221Specs.DESCRIPTOR_TYPES.STREAM_INPUT then

			-- Build error message
			local error_message = "The Descriptor Type shall be set to STREAM_INPUT (0x0005)"

			-- Add control data length error to the subtree
			subtree:add_tvb_expert_info(m._experts[m._FIELD_NAMES.DESCRIPTOR_TYPE_ERROR], buffer(mvu_payload_start + 4, 2), error_message)

			-- Add error message to errors list
			table.insert(errors, error_message)

			-- Return blocking error
			return errors, true, existing_warnings

		end

		--
		-- TODO: Response replicates Command values error
		--

	end

	-- Return non-blocking errors
	return errors, false, existing_warnings

end

-- Return module object
return m
