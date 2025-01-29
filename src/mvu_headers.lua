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
local mIEEE8023Specs = require("ieee8023_specs")
local mConversations = require("mvu_conversations")

-- Init the module object to return
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

-- List of Wireshark field names related to MVU headers
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_NAMES = {
    COMMAND_TYPE              = "mvu.command_type",
    STATUS                    = "mvu.status",
    SPECIFICATIONS_VERSION    = "mvu.specifications_version",
    HAS_ERRORS                = "mvu.has_errors",
    SEQUENCE_ID_DUPLICATE     = "mvu.expert.sequence_id_duplicate",
    CONTROL_DATA_LENGTH_ERROR = "mvu.expert.control_data_length_error",
}

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

-- The index of the last byte in the MVU payload
m._mvu_payload_end = 0

-- The length of the MVU payload
m._mvu_payload_length = 0

-- The index in the packet buffer where the IEEE 1722.1 control data payload starts
m._control_data_start = 0

-- The index in the packet buffer of the last byte of the IEEE 1722.1 control data payload
m._control_data_end = 0

--------------------
-- Public Methods --
--------------------

--- Declare all fields of this feature
function m.DeclareFields()

	------------
	-- FIELDS --
	------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField

	-- Command type
	local command_type_valuestring = mHelpers.GetTableValuesWithNumberKey(mSpecs.COMMAND_TYPES)
	m._fields[m._FIELD_NAMES.COMMAND_TYPE] = mFields.CreateField(ProtoField.uint32(m._FIELD_NAMES.COMMAND_TYPE, "Command Type", base.HEX, command_type_valuestring))

	-- Status code (taken from IEEE 1722.1 header)
	local status_valuestring = mHelpers.GetTableValuesWithNumberKey(mIEEE17221Specs.VENDOR_UNIQUE_STATUS_CODES)
	m._fields[m._FIELD_NAMES.STATUS] = mFields.CreateField(ProtoField.uint8(m._FIELD_NAMES.STATUS, "Status", base.HEX, status_valuestring))

	-- Milan specification revision version
	m._fields[m._FIELD_NAMES.SPECIFICATIONS_VERSION] = mFields.CreateField(ProtoField.string(m._FIELD_NAMES.SPECIFICATIONS_VERSION))

	-- Flag for when the MVU packet has errors
	m._fields[m._FIELD_NAMES.HAS_ERRORS] = mFields.CreateField(ProtoField.bool(m._FIELD_NAMES.HAS_ERRORS))

	-------------------
	-- EXPERT FIELDS --
	-------------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoExpert

	-- Sequence ID duplicate error
	local sequence_id_duplicate_error = ProtoExpert.new(m._FIELD_NAMES.SEQUENCE_ID_DUPLICATE, "Sequence ID duplicate error", expert.group.PROTOCOL, expert.severity.ERROR)
	m._experts[m._FIELD_NAMES.SEQUENCE_ID_DUPLICATE] = mFields.CreateExpertField(m._FIELD_NAMES.SEQUENCE_ID_DUPLICATE, sequence_id_duplicate_error)

	-- Control Data Length error
	local control_data_length_error = ProtoExpert.new(m._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR, "Control Data Length error", expert.group.PROTOCOL, expert.severity.ERROR)
	m._experts[m._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR] = mFields.CreateExpertField(m._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR, control_data_length_error)

end

--- Read the MVU payload bytes and position in buffer
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
function m.ReadMvuPayloadAndPosition(buffer)

	-- Read IEEE1722.1 fields
	local control_data_length = mIEEE17221Fields.GetControlDataLength()

	-- Read payloads positions
	-- Packet structure:
	--  14 bytes for Ethernet header
	--   4 bytes for IEEE1722(.1) subtype data
	--   8 bytes for IEEE1722.1 target_entity_id
	--     (Start of Control Data payload)
	m._control_data_start = 14 + 4 + 8
	--   8 bytes for IEEE1722.1 controller_entity_id
	--   2 bytes for IEEE1722.1 sequence_id
	--   6 bytes for IEEE1722.1 vendor unique protocol ID
	--     (Start of MVU payload)
	m._mvu_payload_start = m._control_data_start + 8 + 2 + 6

	-- The end of the Control Data payload is calculated from the Control Data Length
	-- Capping to end of packet in case control_data_length is unexpectedly too long
	m._control_data_end = math.min(m._control_data_start + control_data_length, buffer:len()) - 1

	-- The MVU payload ends with the Control Data payload
	m._mvu_payload_end = m._control_data_end

	-- Deduce the MVU payload length from start and end positions
	m._mvu_payload_length = math.max(0, 1 + m._mvu_payload_end - m._mvu_payload_start)

	-- Read MVU payload bytes for straight-forward access to MVU bytes in methods
	m._mvu_payload_bytes = buffer:bytes(m._mvu_payload_start, m._mvu_payload_length)

end

--- Create the packet description subtree for MVU
--- Must be called after ReadMvuPayloadAndPosition()
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param tree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @return table mvu_subtree
function m.CreateMvuSubtree(buffer, tree)

		-- Read IEEE 1722.1 field values
		local message_type = mIEEE17221Fields.GetMessageType()

		-- Determine the subtree title
		local subtree_title = "Milan Vendor Unique"
			-- append "(Command)" or "(Response)"
			.. (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND  and " (Command)" or "")
			.. (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and " (Response)" or "")

		-- Add MVU subtree to packet details
		m._subtree = tree:add(mProto.Proto, buffer(m._mvu_payload_start, m._mvu_payload_length), subtree_title)

		-- Return the subtree
		return m._subtree
end

--- Add header fields to the subtree
--- Must be called after ReadMvuPayloadAndPosition() and DeclareFields()
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @param pinfo any Packet info (Pinfo object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
--- @return table<string> errors
--- @return boolean|nil blocking_errors Indicates if one of the returned errors is blocking and should interrupt further packet analysis
function m.AddHeaderFieldsToSubtree(buffer, subtree, pinfo)

	-- Read IEEE 1722.1 field values
	local message_type        = mIEEE17221Fields.GetMessageType()
	local control_data_length = mIEEE17221Fields.GetControlDataLength()

	---
	--- Command Type
	---

	-- Read command type (2 bytes, ignoring first bit)
	m._command_type = bit.band(0x7fff, m._mvu_payload_bytes:int(0, 2))

	-- Write command type and description to the MVU subtree
	subtree:add(m._fields[m._FIELD_NAMES.COMMAND_TYPE], buffer(m._mvu_payload_start, 2), m._command_type)

	---
	--- Command Milan version
	---

	-- Get Milan specification revision implemented by the message
	local milan_version = mSpecs.GetMilanVersionOfCommand(message_type, m._command_type, control_data_length)

	-- If the Milan version was detected
	if type(milan_version) == "string" and #milan_version > 0 then
		-- Write Milan version to the subtree
		subtree:add(m._fields[m._FIELD_NAMES.SPECIFICATIONS_VERSION], milan_version, "Version " .. milan_version)
			--- Mark as a generated field (with data inferred but not contained in the packet)
			:set_generated(true)
	end

	---
	--- Status code
	---

	-- Read status code from IEEE1722.1 header
	m._status_code = bit.rshift(buffer(16, 1):uint(), 3)

	-- Write status to the MVU subtree
	subtree:add(m._fields[m._FIELD_NAMES.STATUS], buffer(16, 1), m._status_code)

	---
	--- Check errors
	---

	local errors = {}

	-- If the Control Data Length is smaller than expected
	-- (the minimum length is 20 bytes for the smallest MVU command)
	local minimum_control_data_length = 20
	if control_data_length < minimum_control_data_length then

		-- Build error message
		local error_message = "Control Data Length (" .. control_data_length .. ") is too small for an MVU message"
			.. " (minimum expected: " .. minimum_control_data_length .. ")"

		-- Add control data length error to the subtree
		subtree:add_tvb_expert_info(m._experts[m._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR], buffer(16, 2), error_message)

		-- Add error message to errors list
		table.insert(errors, error_message)

		-- Return blocking error
		return errors, true

	end

	-- If the Control Data Length is greater than the maximum allowed value
	if control_data_length > 524 then

		-- Builder error message
		local error_message = "Control Data Length (" .. control_data_length .. ") is greater than maximum allowed value (254)"

		-- Add control data length error to the subtree
		subtree:add_tvb_expert_info(m._experts[m._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR], buffer(16, 2), error_message)

		-- Add error message to errors list
		table.insert(errors, error_message)

	end

	-- If the packet does not contain enough bytes to satisfy the Control Data Length
	if m._control_data_start + control_data_length > buffer:len() then

		-- Build error message
		local actual_control_data_payload_size = buffer:len() - m._control_data_start
		local error_message = "Missing bytes at end of packet according to to Control Data Length value"
			.. " (CDL = " .. control_data_length
			.. ", control data payload size: " .. actual_control_data_payload_size .. ")"

		-- Add control data length error to the subtree
		subtree:add_tvb_expert_info(m._experts[m._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR], buffer(16, 2), error_message)

		-- Add error message to errors list
		table.insert(errors, error_message)

	end

	-- If the packet contains more bytes than the Control Data Length is describing
	-- (this is OK if the packet has exactly the minimum Ethernet size of 60 bytes
	-- (without FCS), it is then expected to be zero-padded)
	local control_data_end = math.max(m._control_data_start + control_data_length, mIEEE8023Specs.MINIMUM_FRAME_SIZE_WITHOUT_FCS)
	local remaining_length = buffer:reported_length_remaining(control_data_end)
	if remaining_length > 0 then

		-- Build error message
		local error_message = "The frame contains " .. remaining_length .. " unexpected remaining bytes after the control data payload"

		-- Add control data length error to the subtree
		subtree:add_tvb_expert_info(m._experts[m._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR], buffer(control_data_end, remaining_length), error_message)

		-- Add error message to errors list
		table.insert(errors, error_message)

	end

	-- If the message is a response to a command that the responder does not implement
	if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE
	and m._status_code == mIEEE17221Specs.VENDOR_UNIQUE_STATUS_CODES.NOT_IMPLEMENTED
	then

		-- Get information about the initial command using the conversations module
		local initial_command_data = mConversations.GetConversationMessageData(mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND)

		-- If initial command data was found
		if type(initial_command_data) == "table" then

			-- If the control data length of the initial command was found
			if type(initial_command_data.controlDataLength) == "number" then

				-- If the current response CDL is different from the initial command CDL
				if control_data_length ~= initial_command_data.controlDataLength then

					-- Build error message
					local error_message = "The Control Data Length ("..control_data_length..")"
						.. " shall match that of the initial command (CDL = "..initial_command_data.controlDataLength
						-- Insert initial command frame number if known
						.. (type(initial_command_data.frameNumber) == "number" and ", frame number "..initial_command_data.frameNumber or "")
						.. ") when the PAAD does not implement it."

					-- Add control data length error to the subtree
					subtree:add_tvb_expert_info(m._experts[m._FIELD_NAMES.CONTROL_DATA_LENGTH_ERROR], buffer(control_data_end, remaining_length), error_message)

					-- Add error message to errors list
					table.insert(errors, error_message)

				end
			end
		end

		--  Return breaking error
		return errors, true
	end

	----------------------------------------------------------
	-- Register the message in conversations on first visit --
	----------------------------------------------------------

	-- Init error message
	local register_error_message

	-- If we visit the packet for the first time
	if not pinfo.visited then

		-- Build message metadata to be stored
		local message_metadata = {
			frameNumber = pinfo.number,
			controlDataLength = control_data_length,
		}

		-- Register message and metadata
		register_error_message = mConversations.RegisterMessage(message_metadata, pinfo.number)

	-- If we have already visited the packet
	else
		-- Get the possible error message generated during the registering of this message on first visit
		register_error_message = mConversations.GetRegisterErrorMessageForFrame(pinfo.number)
	end

	-- In case of message registering error
	if register_error_message then

		-- Add sequence ID duplicate error to the subtree
		subtree:add_tvb_expert_info(m._experts[m._FIELD_NAMES.SEQUENCE_ID_DUPLICATE], buffer(26, 10), register_error_message)

		-- Add error message to errors list
		table.insert(errors, register_error_message)

	end

	-- Return list of non-blocking errors if any
	return errors

end

--- Set the value of the Has Errors field and add to subtree
--- @param has_errors boolean
--- @param subtree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function m.SetHasErrorsField(has_errors, subtree)
	if (has_errors) then
		-- Add Has Errors field to the subtree
		subtree:add(m._fields[m._FIELD_NAMES.HAS_ERRORS], true, "The MVU packet has errors!")
			--- Mark as a generated field (with data inferred but not contained in the packet)
			:set_generated(true)
	end
end

--- Alter the packet information object to write MVU details in the packet columns
--- @param pinfo any packet info (PIinfo object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
--- @param errors table<string>|nil List of string errors found during dissecting, worth mentioning in the packet info
function m.WritePacketInfo(pinfo, errors)

	-- Read IEEE 1722.1 field values
	local message_type        = mIEEE17221Fields.GetMessageType()
	local control_data_length = mIEEE17221Fields.GetControlDataLength()

	-- Read MVU header field values
	local command_type = m.GetCommandType()

	-- Get the detected Milan version for this command
	local milan_version = mSpecs.GetMilanVersionOfCommand(message_type, command_type, control_data_length)

	-- Change protocol name from IEEE1722.1 to MVU
	if type(milan_version) == "string" and #milan_version > 0 then
		-- Append command's Milan version if detected
		pinfo.cols["protocol"] = "MVU " .. milan_version
	else
		pinfo.cols["protocol"] = "MVU"
	end

	-- Init info text with command type
	local packet_info = mSpecs.GetCommandTypeDescription(m._command_type)

	-- Append message type to info text
	if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND then
		packet_info = packet_info .. " (Command)"
	end
	if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE then
		packet_info = packet_info .. " (Response)"
	end

	-- Append errors if any to info text
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
