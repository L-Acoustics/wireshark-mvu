--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Constants and information coming from the IEEE 802.3 specifications
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

-- The minimum size of an Ethernet frame
m.MINIMUM_FRAME_SIZE = 64

-- The minimum size of an Ethernet frame (excluding tailing 4 bytes of FCS)
m.MINIMUM_FRAME_SIZE_WITHOUT_FCS = m.MINIMUM_FRAME_SIZE - 4

-- Return module object
return m
