---
--- ieee17221_specs.lua
---
--- Constants and information comming from the IEEE 1722.1 specifications
---

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

-- Return module object
return m
