---
--- control.lua
---
--- Functions for logic control
---

-- Require dependency modules
local mSpecs = require("mvu_specs")
local mIEEE17221Specs = require("ieee17221_specs")
local mIEEE17221Fields = require("ieee17221_fields")
local mHelpers = require("mvu_helpers")

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

--- The minimum supported version of Wireshark
m._minimum_wireshark_version = "4.2.0"

--------------------
-- Public Methods --
--------------------

--- Determines if the current plugin is compatible with the running version of Wireshark
function m.IsWiresharkVersionCompatible()
	-- Get program version
	local wireshark_version = get_version()
	-- If program version is too old
	local version_comparison = mHelpers.CompareVersions(wireshark_version, m._minimum_wireshark_version)
	if type(version_comparison) ~= "number" or version_comparison < 0 then
		-- Not compatible
		return false
	end
	-- Eventually, the Wireshark version is compatible
	return true
end

--- Read the required minimum version of Wireshark compatible with this plugin
--- @return string
function m.GetMinimumWiresharkVersion()
	return m._minimum_wireshark_version
end

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
