--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Functions for compatibility control
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

-- Require dependency modules
local mHelpers = require("helpers")

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

--- The minimum supported version of Wireshark
m._minimum_wireshark_version = "4.4.0"

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
