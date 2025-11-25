--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Constants and information coming from the IEEE 802.1Qat specifications
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

-- List of Base audio stream formats
m.MSRP_FAILURE_CODES = {
	[ 1] = "Insufficient bandwidth",
	[ 2] = "Insufficient Bridge resources",
	[ 3] = "Insufficient bandwidth for Traffic Class",
	[ 4] = "StreamID in use by another Talker",
	[ 5] = "Stream destination_address already in use",
	[ 6] = "Stream preempted by higher rank",
	[ 7] = "Reported latency has changed",
	[ 8] = "Egress port is not AVB capable",
	[ 9] = "Use a different destination_address",
	[10] = "Out of MSRP resources",
	[11] = "Out of MMRP resources",
	[12] = "Cannot store destination_address",
	[13] = "Requested priority is not an SR Class priority",
	[14] = "MaxFrameSize is too large for media",
	[15] = "msrpMaxFanInPorts limit has been reached",
	[16] = "Changes in FirstValue for a registered StreamID",
	[17] = "VLAN is blocked on this egress port",
	[18] = "VLAN tagging is disabled on this egress port",
	[19] = "SR class priority mismatch",
}

-- Return module object
return m
