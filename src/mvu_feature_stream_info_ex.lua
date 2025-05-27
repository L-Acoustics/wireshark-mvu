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
	STREAM_FLAGS                = "mvu.stream.flags",
	STREAM_FLAGS_STREAMING_WAIT = "mvu.stream.flags.streaming_waiting",
	DESCRIPTOR_TYPE             = "mvu.descriptor_type",
	DESCRIPTOR_INDEX            = "mvu.descriptor_index",
	TALKER_ENTITY_ID            = "mvu.stream.talker_entity_id",
	TALKER_STREAM_INDEX         = "mvu.stream.talker_stream_index",
	STREAM_FORMAT               = "mvu.stream.format",
	STREAM_ID                   = "mvu.stream.id",
	MSRP_ACCUMULATED_LATENCY    = "mvu.stream.msrp_accumulated_latency",
	DEST_MAC_ADDRESS            = "mvu.stream.dest_mac",
	MSRP_FAILURE_CODE           = "mvu.stream.msrp_fail_code",
	ACMP_FAILURE_CODE           = "mvu.stream.acmp_fail_code",
	MSRP_FAILURE_BRIDGE_ID      = "mvu.stream.msrp_failure_bridge_id",
	VLAN_ID                     = "mvu.stream.vlan_id",
	SINK_STATE                  = "mvu.stream.sink_state",
	SOURCE_STATE                = "mvu.stream.source_state",
	DESCRIPTOR_TYPE_ERROR       = "mvu.expert.descriptor_type_error",
}

-- Table of offset position and bytes size in the MVU payload for each valid combination of field/command type/message type
m._fields_payload_offset = {
	[m._FIELD_NAMES.STREAM_FLAGS] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] =  2,
		},
	},
	[m._FIELD_NAMES.STREAM_FLAGS_STREAMING_WAIT] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE ] = 2,
		},
	},
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
	[m._FIELD_NAMES.TALKER_STREAM_INDEX] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 16,
		},
	},
	[m._FIELD_NAMES.STREAM_FORMAT] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 20,
		}
	},
	[m._FIELD_NAMES.STREAM_ID] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 28,
		}
	},
	[m._FIELD_NAMES.MSRP_ACCUMULATED_LATENCY] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 36,
		},
	},
	[m._FIELD_NAMES.DEST_MAC_ADDRESS] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 40,
		}
	},
	[m._FIELD_NAMES.MSRP_FAILURE_CODE] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 46,
		}
	},
	[m._FIELD_NAMES.ACMP_FAILURE_CODE] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 47,
		},
	},
	[m._FIELD_NAMES.MSRP_FAILURE_BRIDGE_ID] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 48,
		}
	},
	[m._FIELD_NAMES.VLAN_ID] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 56,
		}
	},
	[m._FIELD_NAMES.SINK_STATE] = {
		[mSpecs.COMMAND_TYPES.GET_STREAM_INPUT_INFO_EX] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 58,
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

	-- Stream Flags
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.STREAM_FLAGS]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.STREAM_FLAGS, "Stream Flags", base.HEX)
	)

	-- Stream Flag: STREAMING_WAIT
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
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

	-- Talker Stream Index
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.TALKER_STREAM_INDEX]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.TALKER_STREAM_INDEX, "Talker Stream Index", base.DEC)
	)

	-- Stream Format
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	local stream_format_valuestring = mHelpers.GetTableValuesWithNumberKey(mAvnuSpecs.BASE_AUDIO_STREAM_FORMATS)
	m._fields[m._FIELD_NAMES.STREAM_FORMAT]
	= mFields.CreateField(
		ProtoField.uint64(m._FIELD_NAMES.STREAM_FORMAT, "Stream Format", base.HEX, stream_format_valuestring)
	)

	-- Stream ID
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.STREAM_ID]
	= mFields.CreateField(
		ProtoField.uint64(m._FIELD_NAMES.STREAM_ID, "Stream ID", base.HEX)
	)

	-- MSRP accumulated latency
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.MSRP_ACCUMULATED_LATENCY]
	= mFields.CreateField(
		ProtoField.uint32(m._FIELD_NAMES.MSRP_ACCUMULATED_LATENCY, "MSRP Accumulated Latency (nanoseconds)", base.DEC)
	)

	-- Destination MAC address
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.DEST_MAC_ADDRESS]
	= mFields.CreateField(
		ProtoField.ether(m._FIELD_NAMES.DEST_MAC_ADDRESS, "Destination MAC Address")
	)

	-- MSRP failure code
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	local msrp_failure_code_valuestring = mHelpers.GetTableValuesWithNumberKey(mIEEE8021QatSpecs.MSRP_FAILURE_CODES)
	m._fields[m._FIELD_NAMES.MSRP_FAILURE_CODE]
	= mFields.CreateField(
		ProtoField.uint8(m._FIELD_NAMES.MSRP_FAILURE_CODE, "MSRP Failure Code", base.DEC, msrp_failure_code_valuestring)
	)

	-- ACMP failure code
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	local acmp_failure_code_valuestring = mHelpers.GetTableValuesWithNumberKey(mIEEE17221Specs.ACMP_FAILURE_CODES)
	m._fields[m._FIELD_NAMES.ACMP_FAILURE_CODE]
	= mFields.CreateField(
		ProtoField.uint8(m._FIELD_NAMES.ACMP_FAILURE_CODE, "ACMP Failure Code", base.DEC, acmp_failure_code_valuestring)
	)

	-- MSRP failure bridge ID
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.MSRP_FAILURE_BRIDGE_ID]
	= mFields.CreateField(
		ProtoField.uint64(m._FIELD_NAMES.MSRP_FAILURE_BRIDGE_ID, "MSRP Failure Bridge ID", base.HEX)
	)

	-- VLAN ID
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	m._fields[m._FIELD_NAMES.VLAN_ID]
	= mFields.CreateField(
		ProtoField.uint16(m._FIELD_NAMES.VLAN_ID, "VLAN ID")
	)

	-- Sink state
	--   Expected in:
	--     GET_STREAM_INPUT_INFO_EX response
	local sink_state_valuestring = mHelpers.GetTableValuesWithNumberKey(mIEEE17221Specs.SINK_STATES)
	m._fields[m._FIELD_NAMES.SINK_STATE]
	= mFields.CreateField(
		ProtoField.uint8(m._FIELD_NAMES.SINK_STATE, "Sink State", base.HEX, sink_state_valuestring)
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
	local add_field_to_tree = function(field, size, execute_on_range)
		-- if the field has an offset position for the command and message types
		if  m._fields_payload_offset[field] ~= nil
		and m._fields_payload_offset[field][command_type] ~= nil
		and m._fields_payload_offset[field][command_type][message_type] ~= nil
		then
			-- Read payload offset position for this field
			local payload_offset = m._fields_payload_offset[field][command_type][message_type]

			-- Write field to the MVU subtree
			subtree:add(m._fields[field], buffer(mvu_payload_start + payload_offset, size))

			-- If any, execute provided function on buffer range
			if (type(execute_on_range) == "function") then
				execute_on_range(buffer(mvu_payload_start + payload_offset, size))
			end
		end
	end

	-- Init variables needed for errors
	local descriptor_type = nil

	-- Add all fields
	add_field_to_tree(m._FIELD_NAMES.STREAM_FLAGS               , 2)
	add_field_to_tree(m._FIELD_NAMES.STREAM_FLAGS_STREAMING_WAIT, 2)
	add_field_to_tree(m._FIELD_NAMES.DESCRIPTOR_TYPE            , 2, function(range) descriptor_type = range:int() end)
	add_field_to_tree(m._FIELD_NAMES.DESCRIPTOR_INDEX           , 2)
	add_field_to_tree(m._FIELD_NAMES.TALKER_ENTITY_ID           , 8)
	add_field_to_tree(m._FIELD_NAMES.TALKER_STREAM_INDEX        , 2)
	add_field_to_tree(m._FIELD_NAMES.STREAM_FORMAT              , 8)
	add_field_to_tree(m._FIELD_NAMES.STREAM_ID                  , 8)
	add_field_to_tree(m._FIELD_NAMES.MSRP_ACCUMULATED_LATENCY   , 4)
	add_field_to_tree(m._FIELD_NAMES.DEST_MAC_ADDRESS           , 6)
	add_field_to_tree(m._FIELD_NAMES.MSRP_FAILURE_CODE          , 1)
	add_field_to_tree(m._FIELD_NAMES.ACMP_FAILURE_CODE          , 1)
	add_field_to_tree(m._FIELD_NAMES.MSRP_FAILURE_BRIDGE_ID     , 8)
	add_field_to_tree(m._FIELD_NAMES.VLAN_ID                    , 2)
	add_field_to_tree(m._FIELD_NAMES.SINK_STATE                 , 1)
	add_field_to_tree(m._FIELD_NAMES.SOURCE_STATE               , 1)

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
