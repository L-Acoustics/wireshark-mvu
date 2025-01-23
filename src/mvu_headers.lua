---
--- mvu_headers.lua
---
--- Handles protocol fields extracted from MVU headers
---

-- Require dependency modules
local mProto = require("mvu_proto")
local mFields = require("mvu_fields")
local mSpecs = require("mvu_specs")
local mIEEE17221Fields = require("ieee17221_fields")
local mIEEE17221Specs = require("ieee17221_specs")
local mHelpers = require("mvu_helpers")

-- Init the module object to return
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

-- Internal list of expert fields
m._experts = {}

-- The MVU subtree
m._subtree = nil

-- The packet's command type
m._command_type = nil

-- The packet's status code
m._status_code = nil

-- The MVU payload bytes
m._mvu_payload_bytes = nil

-- The index in the packer buffer where the MVU payload starts
m._mvu_payload_start = 0

-- The length of the MVU payload
m._mvu_payload_length = 0

-- The index in the paket buffer where the IEEE 1722.1 control data payload starts
m._control_data_start = 0

--------------------
-- Public Methods --
--------------------

--- Declare all fields of this feature
function m.DeclareFields()

	------------
	-- FIELDS --
	------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField

	-- Compand type
	local command_type_valuestring = mHelpers.GetTableValuesWithNumberKey(mSpecs.COMMAND_TYPES)
	m._fields["mvu.command_type"] = mFields.CreateField(ProtoField.uint32("mvu.command_type", "Command Type", base.HEX, command_type_valuestring))

	-- Status code (taken from IEEE 1722.1 header)
	local status_valuestring = mHelpers.GetTableValuesWithNumberKey(mIEEE17221Specs.VENDOR_UNIQUE_STATUS_CODES)
	m._fields["mvu.status"] = mFields.CreateField(ProtoField.uint8("mvu.status", "Status", base.HEX, status_valuestring))

	-- Milan specification revision version
	m._fields["mvu.specifications_version"] = mFields.CreateField(ProtoField.string("mvu.specifications_version"))

	-------------------
	-- EXPERT FIELDS --
	-------------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoExpert

	-- Control Data Length error
	local control_data_length_error = ProtoExpert.new("mvu.expert.control_data_length_error", "Control Data Length error", expert.group.PROTOCOL, expert.severity.ERROR)
	m._experts["mvu.expert.control_data_length_error"] = mFields.CreateExpertField("mvu.expert.control_data_length_error", control_data_length_error)

end

--- Read the MVU payload bytes and position in buffer
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
function m.ReadMvuPayloadAndPosition(buffer)

	-- Read payloads positions
	-- Packet structure:
	--   14 bytes for Ethernet header
	--   4 bytes for IEEE1722 subtype
	--   8 bytes for IEEE1722 stream ID
	--     (Start of Control Data payload)
	m._control_data_start = 14 + 4 + 8
	--   8 bytes for IEEE1722.1 controller ID
	--   2 bytes for IEEE1722.1 sequence ID
	--   6 bytes for IEEE1722.1 vendor protocol ID
	--     (Start of MVU payload)
	m._mvu_payload_start = m._control_data_start + 8 + 2 + 6

	-- Read MVU payload (read to end of packet)
	m._mvu_payload_bytes = buffer:bytes(m._mvu_payload_start)
	m._mvu_payload_length = m._mvu_payload_bytes:len()

end

--- Create the packet description subtree for MVU
--- Must be called after ReadMvuPayloadAndPosition()
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param tree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @return table mvu_subtree
function m.CreateMvuSubtree(buffer, tree)

		-- Read IEEE 1722.1 field values
		local message_type        = mIEEE17221Fields.GetMessageType()

		-- Determine the subtree title
		local subtree_title = "Milan Vendor Unique"
			.. (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND  and " (Command)" or "")
			.. (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and " (Response)" or "")

		-- Add MVU subtree to packet details
		m._subtree = tree:add(mProto.Proto, buffer(m._mvu_payload_start), subtree_title)

		-- Return the subtree
		return m._subtree
end

--- Add header fields to the subtree
--- Must be called after ReadMvuPayloadAndPosition() and DeclareFields()
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @return table<string> errors
function m.AddHeaderFieldsToSubtree(buffer, subtree)

	---
	--- Command Type
	---

	-- Read command type (2 bytes, ignoring first bit)
	m._command_type = bit.band(0x7fff, m._mvu_payload_bytes:int(0, 2))

	-- Write command type and description to the MVU subtree
	subtree:add(m._fields["mvu.command_type"], buffer(m._mvu_payload_start, 2), m._command_type)

	---
	--- Command Milan version
	---

	-- Read IEEE 1722.1 field values
	local message_type = mIEEE17221Fields.GetMessageType()
	local control_data_length = mIEEE17221Fields.GetControldataLength()

	-- Get Milan specification revision implemented by the message
	local milan_version = mSpecs.GetMilanVersionOfCommand(message_type, m._command_type, control_data_length)

	-- If the Milan version was detected
	if type(milan_version) == "string" and #milan_version > 0 then
		-- Write Milan version to the subtree
		subtree:add(m._fields["mvu.specifications_version"], milan_version, "[Version " .. milan_version .. "]")
	end

	---
	--- Status code
	---

	-- Read status code from IEEE1722.1 header
	m._status_code = bit.rshift(buffer(16, 1):uint(), 3)

	-- Write status to the MVU subtree
	subtree:add(m._fields["mvu.status"], buffer(16, 1), m._status_code)

	---
	--- Check errors
	---

	local errors = {}

	-- Read IEEE 1722.1 field values
	local control_data_length = mIEEE17221Fields.GetControldataLength()

	-- If the Control data Length is smaller than expected
	-- (the minimum length is 20 bytes for the smallest MVU command)
	local minimum_control_data_length = 20
	if control_data_length < minimum_control_data_length then

		-- Build eror message
		local error_message = "Control Data Length value is too small"
			.. " (CDL = " .. control_data_length
			.. ", minimum expected: " .. minimum_control_data_length .. ")"

		-- Add control data length error to the subtree
		subtree:add_tvb_expert_info(m._experts["mvu.expert.control_data_length_error"], buffer(16, 2), error_message)

		-- Add error message to errors lise
		table.insert(errors, error_message)

	-- If the Control Data Length is greater than the control data payload
	elseif m._control_data_start + control_data_length > buffer:len() then

		-- Build eror message
		local actual_control_data_payload_size = buffer:len() - m._control_data_start
		local error_message = "Missing bytes at end of packet according to to Control Data Length value"
			.. " (CDL = " .. control_data_length
			.. ", control data payload size: " .. actual_control_data_payload_size .. ")"

		-- Add control data length error to the subtree
		subtree:add_tvb_expert_info(m._experts["mvu.expert.control_data_length_error"], buffer(16, 2), error_message)

		-- Add error message to errors lise
		table.insert(errors, error_message)
	end

	-- Return list of errors if any
	return errors

end

--- Alter the packet information object to write MVU details in the packet columns
--- @param pinfo any packet info (PIinfo object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
--- @param errors table<string>|nil List of string errors found during dissecting, worth mentioning in the packet info
function m.WritePacketInfo(pinfo, errors)

	-- Change protocol name to MVU
	pinfo.cols["protocol"] = "MVU"

	-- Read IEEE 1722.1 field values
	local message_type = mIEEE17221Fields.GetMessageType()

	-- Init info text with command type
	local packet_info = mSpecs.GetCommandTypeDescription(m._command_type)

	-- Append message type
	if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND then
		packet_info = packet_info .. " (Command)"
	end
	if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE then
		packet_info = packet_info .. " (Response)"
	end

	-- Append errors if any
	if type(errors) == "table" and #errors > 0 then
		packet_info = packet_info .. " [ERRORS: "
		for _,error in pairs(errors) do
			packet_info = packet_info .. error .. " ; "
		end
		packet_info = packet_info:sub(1, -4) .. "]"
	end

	-- Overwrite packet info column text
	pinfo.cols["info"] = packet_info

end

--- Read the packet's command type
--- @return number|nil command_type
function m.GetCommandType()
	return m._command_type
end

--- Read the packet's status code
--- @return number|nil status_code
function m.GetStatusCode()
	return m._status_code
end

--- Read the MVU payload portion of the packet buffer and its location in the buffer
--- @return any|nil mvu_payload_bytes, number mvu_payload_start, number mvu_payload_length
function m.GetMvuPayload()
	return m._mvu_payload_bytes, m._mvu_payload_start, m._mvu_payload_length
end

-- Return the module object
return m
