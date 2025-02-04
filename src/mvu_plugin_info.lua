--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Constants and information about this Wireshark plugin
	---

	Authors: Benjamin Landrot

	Licensed under the GNU General Public License (GPL) version 2
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express of implied.
	See the License for the specific language governing permissions and
	limitations under the License.

]]

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

m._info = {
	version = "1.2.0.0",
	author = "L-Acoustics",
	description = "Lua plugin for dissecting Milan Vendor Unique information in IEEE1722.1 frames in Wireshark",
	repository = "https://github.com/L-Acoustics/wireshark-mvu"
}

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
