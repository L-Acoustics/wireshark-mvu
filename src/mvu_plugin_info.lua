---
--- mvu_plugin_info.lua
---
--- Constants and information about this Wireshark plugin
---

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

m._info = {
	version = "1.0.0.0",
	author = "L-Acoustics",
	description = "Lua plugin for dissecting Milan Vendor Unique information in IEEE1722.1 frames in WireShark",
	repository = "http://serv-gitlab-rddev/software/3rdparty/wireshark-mvu"
}

------
--------------------
-- Public Methods --
--------------------

--- Register plugin information in Wireshark
function m.RegisterPluginInfo()
    set_plugin_info(m._info)
end

--- Get plugin version information
--- @return string plugin_version
function m.GetVersion()
	return m._info.version
end

-- Return module object
return m
