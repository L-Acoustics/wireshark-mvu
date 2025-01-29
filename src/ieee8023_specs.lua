---
--- ieee8023_specs.lua
---
--- Constants and information coming from the IEEE 802.3 specifications
---

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
