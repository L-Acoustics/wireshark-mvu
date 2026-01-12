--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Functions for logic control
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
local mIEEE1722Fields  = require("ieee1722_fields")
local mIEEE1722Specs   = require("ieee1722_specs")
local mIEEE17221Fields = require("ieee17221_fields")

-- Init module object
local m = {}

--------------------
-- Public Methods --
--------------------

--- Indicate if the current dissected packet is an AECP packet
--- @return boolean is_aecp_packet
function m.IsAecpPacket()

	-- Get IEEE 1722 field values
	local avtp_subtype = mIEEE1722Fields.GetAvtpSubtype()

	-- Get IEEE 1722.1 field values
	local control_data_length = mIEEE17221Fields.GetControlDataLength()
	local message_type        = mIEEE17221Fields.GetMessageType()

	-- It is an AECP packet if:
	-- > The AVTP Subtype is AECP
	-- > The Control Data Field is valid
	-- > The message type is valid
	return avtp_subtype == mIEEE1722Specs.AVTP_SUBTYPES.AECP
	   and control_data_length ~= nil
	   and message_type ~= nil
end

-- Return module object
return m
