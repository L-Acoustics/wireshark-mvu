--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Constants and information coming from the IEEE 1722.1 specifications
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
