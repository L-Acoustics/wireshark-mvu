---
--- ieee8023_specs.lua
---
--- Constants and information comming from the IEEE 802.3 specifications
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

-- The minimum size of an Ethernet frame
m.MINIMUM_FRAME_SIZE = 64

-- The minimum size of an Ethernet frame (excluding tailing 4 bytes of FCS)
m.MINIMUM_FRAME_SIZE_WITHOUT_FCS = m.MINIMUM_FRAME_SIZE - 4

-- Return module object
return m
