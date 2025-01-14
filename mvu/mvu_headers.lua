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

-- Init the module object to return
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

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

--------------------
-- Public Methods --
--------------------

--- Declare all fields of this feature
function m.DeclareFields()

	-- Extract command types for field's valuestrnig argument
	local command_type_valuestring = {}
	for k,v in pairs(mSpecs.COMMAND_TYPES) do
		if type(k) == "number" then
			command_type_valuestring[k] = v
		end
	end

	-- Extract status codes for field's valuestrnig argument
	local status_valuestring = {}
	for k,v in pairs(mSpecs.STATUS_CODES) do
		if type(k) == "number" then
			status_valuestring[k] = v
		end
	end

	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField
	m._fields["mvu.command_type"] = mFields.CreateField(ProtoField.uint32("mvu.command_type", "Command Type", base.HEX, command_type_valuestring))
	m._fields["mvu.status"]       = mFields.CreateField(ProtoField.uint8("mvu.status", "Status", base.HEX, status_valuestring))

end

--- Create the packet description subtree for MVU
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param tree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @return table mvu_subtree
function m.CreateMvuSubtree(buffer, tree)

		-- Read IEEE 1722.1 field values
		local control_data_length = mIEEE17221Fields.GetControldataLength()
		local message_type        = mIEEE17221Fields.GetMessageType()

		-- Get MVU payload bytes from buffer
		-- Skip:
		--   14 bytes for Ethernet header
		--   4 bytes for IEEE1722 subtype
		--   8 bytes for IEEE1722 stream ID
		--   8 bytes for IEEE1722.1 controller ID
		--   2 bytes for IEEE1722.1 sequence ID
		--   6 bytes for IEEE1722.1 vendor protocol ID
		local mvu_payload_start = 14 + 4 + 8 + 8 + 2 + 6
		-- Note: the control_data_length includes IEEE1722.1 headers so the MVU payload size is the control data length - IEEE1722.1 headers length (16 bytes)
		local mvu_payload_length = control_data_length - 16

		-- Determine the subtree title
		local subtree_title = "Milan Vendor Unique"
			.. (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND  and " (Command)" or "")
			.. (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and " (Response)" or "")

		-- Add MVU subtree to packet details
		m._subtree = tree:add(mProto.Proto, buffer(mvu_payload_start, mvu_payload_length), subtree_title)

		-- Return the subtree
		return m._subtree
end

--- Add header fields to the subtree
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @return number command_type, number status_code
function m.AddHeaderFieldsToSubtree(buffer, subtree)

	-- Read IEEE 1722.1 field values
	local control_data_length = mIEEE17221Fields.GetControldataLength()

	-- Get MVU payload bytes from buffer
	-- Skip:
	--   14 bytes for Ethernet header
	--   4 bytes for IEEE1722 subtype
	--   8 bytes for IEEE1722 stream ID
	--   8 bytes for IEEE1722.1 controller ID
	--   2 bytes for IEEE1722.1 sequence ID
	--   6 bytes for IEEE1722.1 vendor protocol ID
	m._mvu_payload_start = 14 + 4 + 8 + 8 + 2 + 6
	-- Note: the control_data_length includes IEEE1722.1 headers so the MVU payload size is the control data length - IEEE1722.1 headers length (16 bytes)
	local mvu_payload_length = control_data_length - 16
	m._mvu_payload_bytes = buffer:bytes(m._mvu_payload_start, mvu_payload_length)

	---
	--- Command Type
	---

	-- Read command type (2 bytes, ignoring first bit)
	m._command_type = bit.band(0x7fff, m._mvu_payload_bytes:int(0, 2))

	-- Write command type and description to the MVU subtree
	subtree:add(m._fields["mvu.command_type"], buffer(m._mvu_payload_start, 2), m._command_type)

	---
	--- Status code
	---

	-- Read status code from IEEE1722.1 header
	m._status_code = bit.rshift(buffer(16, 1):uint(), 3)

	-- Write status to the MVU subtree
	subtree:add(m._fields["mvu.status"], buffer(16, 1), m._status_code)

	-- Return the value of the inserted fields
	return m._command_type, m._status_code
end

--- Write the packet information column with the packet's information
--- @param pinfo any
function m.WritePacketInfo(pinfo)

	-- Read IEEE 1722.1 field values
	local message_type = mIEEE17221Fields.GetMessageType()

	-- Init info text with command type
	local packet_info = "Milan Vendor Unique: " .. mSpecs.GetCommandTypeDescription(m._command_type)

	-- Append message type
	if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND then
		packet_info = packet_info .. " (Command)"
	end
	if message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE then
		packet_info = packet_info .. " (Response)"
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

--- Read the MVU payload portion of the packet buffer
--- @return any|nil mvu_payload_bytes, number mvu_payload_start
function m.GetMvuPayloadBytes()
	return m._mvu_payload_bytes, m._mvu_payload_start
end

-- Return the module object
return m
