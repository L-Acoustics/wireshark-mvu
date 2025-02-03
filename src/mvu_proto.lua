---
--- mvu_proto.lua
--- 
--- Contains the MVU Wireshark protocol object and fields
--- 

-- Stop here if the version of Wireshark is not supported
local mCompatibility = require("mvu_compatibility")
if not mCompatibility.IsWiresharkVersionCompatible() then
	return
end

-- Init the module object to return
local m = {}

-----------------------
-- Public Properties --
-----------------------

-- Create proto object for the dissector
-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_fn_proto___call_name__description_
m.Proto = Proto("mvu", "Milan Vendor Unique (MVU)")

-- Return the module object
return m