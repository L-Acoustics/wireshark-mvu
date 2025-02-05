--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Declares and implements 'mvu' protocol for displaying information
		related to Milan Vendor Unique data in IEEE 1722.1 packets
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
local mPluginInfo = require("mvu_plugin_info")
local mProto = require("mvu_proto")
local mFields = require("mvu_fields")
local mSpecs = require("mvu_specs")
local mHeaders = require("mvu_headers")
local mIEEE17221Fields = require("ieee17221_fields")
local mMilanInfo = require("mvu_feature_milan_info")
local mSystemUniqueId = require("mvu_feature_system_unique_id")
local mClockReferenceInfo = require("mvu_feature_clock_reference_info")
local mConversations = require("mvu_conversations")
local mControl = require("mvu_control")
local mCompatibility = require("mvu_compatibility")

-- Check compatibility with Wireshark version
if not mCompatibility.IsWiresharkVersionCompatible() then
	-- Report incompatibility of plugin to user
	local incompatibility_message =
		"The MVU plugin (mvu.lua) requires Wireshark version ".. mCompatibility.GetMinimumWiresharkVersion()  .." or newer." .. "\n"
		.. "To analyze MVU packets, please update the version of Wireshark."
	report_failure(incompatibility_message)
	return
end

-- Load IEEE 1722.1 fields needed for dissecting MVU packets
mIEEE17221Fields.LoadAllFields()

-- Declare MVU fields
mHeaders.DeclareFields()
mMilanInfo.DeclareFields()
mSystemUniqueId.DeclareFields()
mClockReferenceInfo.DeclareFields()

-- Register declared fields to protocol
mFields.RegisterAllFieldsInProtocol()

--------------------
-- IMPLEMENTATION --
--------------------

--- The init routine of the dissector
function mProto.Proto.init()
	-- Clear conversations
	mConversations.ClearConversations()
end

--- Implementation of protocol's dissector
--- @see documentation https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_attrib_proto_dissector
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param pinfo table The packet info (PInfo object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
--- @param tree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function mProto.Proto.dissector(buffer, pinfo, tree)

	-- If we are dissecting an MVU packet
	if mControl.IsMvuPacket() then

		-- Init table of errors that we may encounter during dissecting
		local errors = {}
		local blocking_errors

		-------------
		-- Headers --
		-------------

		-- Read MVU payload and positions
		mHeaders.ReadMvuPayloadAndPosition(buffer)

		-- Add MVU subtree to packet details
		local mvuSubtree = mHeaders.CreateMvuSubtree(buffer, tree)

		-- Add header fields to subtree
		errors, blocking_errors = mHeaders.AddHeaderFieldsToSubtree(buffer, mvuSubtree, pinfo)

		--------------
		-- Features --
		--------------

		-- Add Milan Info fields to subtree
		if not blocking_errors then
			errors, blocking_errors = mMilanInfo.AddFieldsToSubtree(buffer, mvuSubtree, errors)
		end

		-- Add System Unique Id fields to subtree
		if not blocking_errors then
			error, blocking_errors = mSystemUniqueId.AddFieldsToSubtree(buffer, mvuSubtree, errors)
		end

		-- Add Clock Reference Info fields to subtree
		if not blocking_errors then
			errors, blocking_errors = mClockReferenceInfo.AddFieldsToSubtree(buffer, mvuSubtree, errors)
		end

		-- Insert message in case there are unimplemented extra bytes at end of payload
		if not blocking_errors then
			mControl.InsertUnimplementedExtraBytesMessage(mvuSubtree)
		end

		-----------------
		-- Packet Info --
		-----------------

		-- Aff the Has Errors field to the subtree
		local has_errors = #errors > 0
		mHeaders.SetHasErrorsField(has_errors, mvuSubtree)

		-- Write to packet info columns
		mHeaders.WritePacketInfo(pinfo, errors)

		-----------------
		-- Plugin Info --
		-----------------

		-- Register plugin information into Wireshark
		mPluginInfo.RegisterPluginInfo()

		-- Add plugin information to the subtree
		mvuSubtree:add("MVU plugin version " .. mPluginInfo.GetVersion() .. ", supports Milan Specifications up to version " .. mSpecs.SPEC_VERSION)
			--- Mark as a generated field (with data inferred but not contained in the packet)
			:set_generated(true)

	end

end

-- Finally, register protocol as a postdissector
-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_fn_register_postdissector_proto___allfields__
register_postdissector(mProto.Proto)
