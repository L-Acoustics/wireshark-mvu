---
--- ieee17221_specs.lua
---
--- Constants and information comming from the IEEE 1722.1 specifications
---

-- Stop here if the version of Wireshark is not supported
local mCompatibility = require("mvu_compatibility")
if not mCompatibility.IsWiresharkVersionCompatible() then
	return
end

-- Init module object
local m = {}

-----------------------
-- Public Properties --
-----------------------

-- List of known IEEE 1722.1 AECP commands
m.AECP_MESSAGE_TYPES = {
    VENDOR_UNIQUE_COMMAND  = 6, [6] = "VENDOR_UNIQUE_COMMAND",
    VENDOR_UNIQUE_RESPONSE = 7, [7] = "VENDOR_UNIQUE_RESPONSE",
}

-- Vendor Unique status codes
m.VENDOR_UNIQUE_STATUS_CODES = {
    SUCCESS         = 0, [0] = "SUCCESS",
    NOT_IMPLEMENTED = 1, [1] = "NOT_IMPLEMENTED"
}

-- Return module object
return m
