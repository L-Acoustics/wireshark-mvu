--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Constants and information coming from the IEEE Avnu specifications
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
m.BASE_AUDIO_STREAM_FORMATS = {
	[0x0205022000406000] = "AAF, 48kHz, PCM-INT-32, 1 channel",
	[0x0205022000806000] = "AAF, 48kHz, PCM-INT-32, 2 channel",
	[0x0205022001006000] = "AAF, 48kHz, PCM-INT-32, 4 channel",
	[0x0205022001806000] = "AAF, 48kHz, PCM-INT-32, 6 channel",
	[0x0205022002006000] = "AAF, 48kHz, PCM-INT-32, 8 channel",
	[0x020702200040C000] = "AAF, 96kHz, PCM-INT-32, 1 channel",
	[0x020702200080C000] = "AAF, 96kHz, PCM-INT-32, 2 channel",
	[0x020702200100C000] = "AAF, 96kHz, PCM-INT-32, 4 channel",
	[0x020702200180C000] = "AAF, 96kHz, PCM-INT-32, 6 channel",
	[0x020702200200C000] = "AAF, 96kHz, PCM-INT-32, 8 channel",
	[0x0209022000418000] = "AAF, 192kHz, PCM-INT-32, 1 channel",
	[0x0209022000818000] = "AAF, 192kHz, PCM-INT-32, 2 channel",
	[0x0209022001018000] = "AAF, 192kHz, PCM-INT-32, 4 channel",
	[0x0209022001818000] = "AAF, 192kHz, PCM-INT-32, 6 channel",
	[0x0209022002018000] = "AAF, 192kHz, PCM-INT-32, 8 channel"
}

-- Return module object
return m
