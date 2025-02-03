---
--- mvu_compatibility.lua
---
--- Functions for compatibility control
---

-- Require dependency modules
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

-- Return module object
return m
