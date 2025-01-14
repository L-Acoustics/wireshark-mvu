---
--- control.lua
---
--- Functions for logic control
---

-- Require dependency modules
local mPluginInfo = require("mvu_plugin_info")
local mProto = require("mvu_proto")
local mFields = require("mvu_fields")
local mSpecs = require("mvu_specs")
local mHeaders = require("mvu_headers")
local mIEEE17221Specs = require("ieee17221_specs")
local mIEEE17221Fields = require("ieee17221_fields")

-- Init module object
local m = {}

-----------------------
-- Public Properties --
-----------------------

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

-- Return module object
return m
