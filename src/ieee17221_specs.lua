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
    NOT_IMPLEMENTED = 1, [1] = "NOT_IMPLEMENTED",
	PAYLOAD_ERROR   = 2, [2] = "PAYLOAD_ERROR",
}

-- Descriptor types
m.DESCRIPTOR_TYPES = {
	ENTITY               =  0, [ 0] = "ENTITY",
	CONFIGURATION        =  1, [ 1] = "CONFIGURATION",
	AUDIO_UNIT           =  2, [ 2] = "AUDIO_UNIT",
	VIDEO_UNIT           =  3, [ 3] = "VIDEO_UNIT",
	SENSOR_UNIT          =  4, [ 4] = "SENSOR_UNIT",
	STREAM_INPUT         =  5, [ 5] = "STREAM_INPUT",
	STREAM_OUTPUT        =  6, [ 6] = "STREAM_OUTPUT",
	JACK_INPUT           =  7, [ 7] = "JACK_INPUT",
	JACK_OUTPUT          =  8, [ 8] = "JACK_OUTPUT",
	AVB_INTERFACE        =  9, [ 9] = "AVB_INTERFACE",
	CLOCK_SOURCE         = 10, [10] = "CLOCK_SOURCE",
	MEMORY_OBJECT        = 11, [11] = "MEMORY_OBJECT",
	LOCALE               = 12, [12] = "LOCALE",
	STRINGS              = 13, [13] = "STRINGS",
	STREAM_PORT_INPUT    = 14, [14] = "STREAM_PORT_INPUT",
	STREAM_PORT_OUTPUT   = 15, [15] = "STREAM_PORT_OUTPUT",
	EXTERNAL_PORT_INPUT  = 16, [16] = "EXTERNAL_PORT_INPUT",
	EXTERNAL_PORT_OUTPUT = 17, [17] = "EXTERNAL_PORT_OUTPUT",
	INTERNAL_PORT_INPUT  = 18, [18] = "INTERNAL_PORT_INPUT",
	INTERNAL_PORT_OUTPUT = 19, [19] = "INTERNAL_PORT_OUTPUT",
	AUDIO_CLUSTER        = 20, [20] = "AUDIO_CLUSTER",
	VIDEO_CLUSTER        = 21, [21] = "VIDEO_CLUSTER",
}

-- ACMP failure codes
m.ACMP_FAILURE_CODES = {
	SUCCESS                       =  0 ,[ 0] = "SUCCESS",
	LISTENER_UNKNOWN_ID           =  1 ,[ 1] = "LISTENER_UNKNOWN_ID",
	TALKER_UNKNOWN_ID             =  2 ,[ 2] = "TALKER_UNKNOWN_ID",
	TALKER_DEST_MAC_FAIL          =  3 ,[ 3] = "TALKER_DEST_MAC_FAIL",
	TALKER_NO_STREAM_INDEX        =  4 ,[ 4] = "TALKER_NO_STREAM_INDEX",
	TALKER_NO_BANDWIDTH           =  5 ,[ 5] = "TALKER_NO_BANDWIDTH",
	TALKER_EXCLUSIVE              =  6 ,[ 6] = "TALKER_EXCLUSIVE",
	LISTENER_TALKER_TIMEOUT       =  7 ,[ 7] = "LISTENER_TALKER_TIMEOUT",
	LISTENER_EXCLUSIVE            =  8 ,[ 8] = "LISTENER_EXCLUSIVE",
	STATE_UNAVAILABLE             =  9 ,[ 9] = "STATE_UNAVAILABLE",
	NOT_CONNECTED                 = 10 ,[10] = "NOT_CONNECTED",
	NO_SUCH_CONNECTION            = 11 ,[11] = "NO_SUCH_CONNECTION",
	COULD_NOT_SEND_MESSAGE        = 12 ,[12] = "COULD_NOT_SEND_MESSAGE",
	TALKER_MISBEHAVING            = 13 ,[13] = "TALKER_MISBEHAVING",
	LISTENER_MISBEHAVING          = 14 ,[14] = "LISTENER_MISBEHAVING",
	CONTROLLER_NOT_AUTHORIZED     = 16 ,[16] = "CONTROLLER_NOT_AUTHORIZED",
	INCOMPATIBLE_REQUEST          = 17 ,[17] = "INCOMPATIBLE_REQUEST",
	LISTENER_INVALID_CONNECTION   = 18 ,[18] = "LISTENER_INVALID_CONNECTION",
	LISTENER_CAN_ONLY_LISTEN_ONCE = 19 ,[19] = "LISTENER_CAN_ONLY_LISTEN_ONCE",
	NOT_SUPPORTED                 = 31 ,[31] = "NOT_SUPPORTED",
}

-- Input stream/sink states
m.SINK_STATES = {
	NOT_BOUND                   = 0, [0] = "NOT_BOUND",
	WAITING_MATCHING_ADP_TALKER = 1, [1] = "WAITING_MATCHING_ADP_TALKER",
	PROBING_ACTIVE              = 2, [2] = "PROBING_ACTIVE",
	PROBING_PASSIVE             = 3, [3] = "PROBING_PASSIVE",
	PROBING_FAILED              = 4, [4] = "PROBING_FAILED",
	PROBING_SUCCESS             = 5, [5] = "PROBING_SUCCESS",
	WAITING_SRP_TALKER          = 6, [6] = "WAITING_SRP_TALKER",
	REGISTERING_FAILED          = 7, [7] = "REGISTERING_FAILED",
	REGISTERING_SUCCESS         = 8, [8] = "REGISTERING_SUCCESS",
}

-- Output stream/source states
m.SOURCE_STATES = {
	WAITING_MAAP_DEST_ADDR      = 0, [0] = "WAITING_MAAP_DEST_ADDR",
	READY                       = 1, [1] = "READY",
	WAITING_SRP_TALKER          = 2, [2] = "WAITING_SRP_TALKER",
	WAITING_SRP_LISTENER        = 3, [3] = "WAITING_SRP_LISTENER",
	DECLARING_TALKER_FAILED     = 4, [4] = "DECLARING_TALKER_FAILED",
	REGISTERING_FAILED_LISTENER = 5, [5] = "REGISTERING_FAILED_LISTENER",
	REGISTERING_SUCCESS         = 6, [6] = "REGISTERING_SUCCESS",
}

-- Return module object
return m
