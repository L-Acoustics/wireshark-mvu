--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Handle fields related to GET_MILAN_INFO commands
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

-- List of fields related to GET_MILAN_INFO commands/responses
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_NAMES = {
    PROTOCOL_VERSION                = "mvu.protocol_version",
    FEATURE_FLAGS                   = "mvu.feature_flags",
    FEATURE_REDUNDANCY              = "mvu.feature.redundancy",
    FEATURE_TALKER_DYNAMIC_MAPPINGS = "mvu.feature.talker_dynamic_mappings",
    FEATURE_MVU_BINDING             = "mvu.feature.binding",
    FEATURE_TALKER_SIGNAL_PRESENCE  = "mvu.feature.talker_signal_presence",
    PAAD_CERTIFICATION_VERSION      = "mvu.paad_certification_version",
    PAAD_SPECIFICATION_VERSION      = "mvu.paad_specification_version",
}

-- Table of offset position and bytes size in the MVU payload for each valid combination of field/message type
m._fields_payload_offset = {
	[m._FIELD_NAMES.PROTOCOL_VERSION] = {
		[mSpecs.COMMAND_TYPES.GET_MILAN_INFO] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND ] = 4,
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 4,
		}
	},
	[m._FIELD_NAMES.FEATURE_FLAGS] = {
		[mSpecs.COMMAND_TYPES.GET_MILAN_INFO] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 8,
		}
	},
	[m._FIELD_NAMES.FEATURE_REDUNDANCY] = {
		[mSpecs.COMMAND_TYPES.GET_MILAN_INFO] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 8,
		}
	},
	[m._FIELD_NAMES.FEATURE_TALKER_DYNAMIC_MAPPINGS] = {
		[mSpecs.COMMAND_TYPES.GET_MILAN_INFO] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 8,
		}
	},
	[m._FIELD_NAMES.FEATURE_MVU_BINDING] = {
		[mSpecs.COMMAND_TYPES.GET_MILAN_INFO] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 8,
		}
	},
	[m._FIELD_NAMES.FEATURE_TALKER_SIGNAL_PRESENCE] = {
		[mSpecs.COMMAND_TYPES.GET_MILAN_INFO] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 8,
		}
	},
	[m._FIELD_NAMES.PAAD_CERTIFICATION_VERSION] = {
		[mSpecs.COMMAND_TYPES.GET_MILAN_INFO] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 12,
		}
	},
	[m._FIELD_NAMES.PAAD_SPECIFICATION_VERSION] = {
		[mSpecs.COMMAND_TYPES.GET_MILAN_INFO] = {
			[mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE] = 16,
		}
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

	-- Feature: MVU binding and unbinding
	--   Expected in:
	--     GET_MILAN_INFO response
	m._fields[m._FIELD_NAMES.FEATURE_MVU_BINDING]
	= mFields.CreateField(
		ProtoField.bool(
			m._FIELD_NAMES.FEATURE_MVU_BINDING,
			"FEATURE_MVU_BINDING",
			32,         -- parent bitfield size
			nil,        -- table of value strings
			0x00000004) -- bit mask for this field
	)

	-- Feature: Monitoring signal presence on audio channels
	--   Expected in:
	--     GET_MILAN_INFO response
	m._fields[m._FIELD_NAMES.FEATURE_TALKER_SIGNAL_PRESENCE]
	= mFields.CreateField(
		ProtoField.bool(
			m._FIELD_NAMES.FEATURE_TALKER_SIGNAL_PRESENCE,
			"FEATURE_TALKER_SIGNAL_PRESENCE",
			32,         -- parent bitfield size
			nil,        -- table of value strings
			0x00000008) -- bit mask for this field
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

	-- Specification version (the version number of the Milan certifications that the PAAD-AE supports)
	--   Expected in:
	--     GET_MILAN_INFO response
	m._fields[m._FIELD_NAMES.PAAD_SPECIFICATION_VERSION]
	= mFields.CreateField(
		ProtoField.string(
			m._FIELD_NAMES.PAAD_SPECIFICATION_VERSION,
			"PAAD specification version",
			base.ASCII,
			"The version number of the Milan certifications that the PAAD-AE supports"
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

	----------------------------
	-- Add fields to the tree --
	----------------------------

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

	--- Extract a specifications version from raw byte range of size 4
	--- @param range any
	--- @return string|nil
	local extract_specifications_version = function(range)
		-- Read version numbers
		local version_numbers = { string.unpack("bbbb", range:raw()) }
		-- If numbers are not zeros
		if version_numbers[1] > 0 then
			-- Build and return string version
			return string.format(
				"%d.%d",
				version_numbers[1],
				version_numbers[2]
			)
		end
	end

	-- Add all fields to the tree
	-- Version 1.0
	if (mHelpers.CompareVersions(milan_version, "1") >= 0) then
		add_field_to_tree(m._FIELD_NAMES.PROTOCOL_VERSION               , 4)
		add_field_to_tree(m._FIELD_NAMES.FEATURE_FLAGS                  , 4)
		add_field_to_tree(m._FIELD_NAMES.FEATURE_REDUNDANCY             , 4)
		add_field_to_tree(m._FIELD_NAMES.FEATURE_TALKER_DYNAMIC_MAPPINGS, 4)
		add_field_to_tree(m._FIELD_NAMES.FEATURE_MVU_BINDING            , 4)
		add_field_to_tree(m._FIELD_NAMES.FEATURE_TALKER_SIGNAL_PRESENCE , 4)
		add_field_to_tree(m._FIELD_NAMES.PAAD_CERTIFICATION_VERSION     , 4, nil, extract_specifications_version, true)
	end
	-- Version 1.2.10
	if (mHelpers.CompareVersions(milan_version, "1.2.10") >= 0) then
		add_field_to_tree(m._FIELD_NAMES.PAAD_SPECIFICATION_VERSION, 4, nil, extract_specifications_version, true)
	end

	-- Return non-blocking errors
	return errors

end

-- Return module object
return m
