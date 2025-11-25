--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Declares and implements 'aecp-diagnostics' protocol for displaying
		diagnostics information on IEEE 1722.1 AECP packets
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
local mAlgorithms                = require("aecp-diagnostics_algorithms")
local mPluginInfo                = require("aecp-diagnostics_plugin-info")
local mProto                     = require("aecp-diagnostics_proto")
local mHeaders                   = require("aecp-diagnostics_headers")
local mFields                    = require("aecp-diagnostics_fields")
local mControl                   = require("aecp-diagnostics_control")
local mCompatibility             = require("aecp-diagnostics_compatibility")
local mConversations             = require("aecp-diagnostics_conversations")
local mFeatureAssociatedMessages = require("aecp-diagnostics_feature_associated-messages")
local mFeatureTiming             = require("aecp-diagnostics_feature_timing")
local mfeatureRetryCommands      = require("aecp-diagnostics_feature_retry-commands")
local mfeatureConversations      = require("aecp-diagnostics_feature_conversations")
local mIEEE1722Fields            = require("ieee1722_fields")
local mIEEE17221Fields           = require("ieee17221_fields")
local mMvuSpecs                  = require("mvu_specs")

-- Check compatibility with Wireshark version
if not mCompatibility.IsWiresharkVersionCompatible() then
	-- Report incompatibility of plugin to user
	local incompatibility_message =
		"The AECP Diagnostics plugin (aecp-diagnostics.lua) requires Wireshark version ".. mCompatibility.GetMinimumWiresharkVersion()  .." or newer." .. "\n"
		.. "Please update the version of Wireshark."
	report_failure(incompatibility_message)
	return
end

-- Load IEEE 1722 and 1722.1 fields needed for dissecting AECP packets
mIEEE1722Fields.LoadAllFields()
mIEEE17221Fields.LoadAllFields()

-- Declare all fields
mHeaders.DeclareFields()
mFeatureAssociatedMessages.DeclareFields()
mfeatureConversations.DeclareFields()
mFeatureTiming.DeclareFields()
mfeatureRetryCommands.DeclareFields()

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

	-- If we are dissecting an AECP packet
	if mControl.IsAecpPacket() then

		-- Init table of errors that we may encounter during dissecting
		local errors = {}
		local blocking_errors

		-------------
		-- Headers --
		-------------

		-- Add subtree to packet details
		local subtree = mHeaders.CreateAecpDiagnosticsSubtree(buffer, tree)

		------------------
		-- Conversation --
		------------------

		-- On first visit
		if not pinfo.visited then
			-- Unless the message is unsolicited
			local unsolicited_flag = mIEEE17221Fields.GetUnsolicitedFlag()
			if unsolicited_flag ~= true then
				-- Add initial metadata to conversation
				local conversation = mConversations.AddMessageMetadataToConversation(pinfo, {
					frame_number = pinfo.number,
					is_mvu_message = mMvuSpecs.IsMvuMessage(),
				})

				-- Process additional metadata based on existing messages
				if type(conversation)=="table" then
					local conversation_has_errors = mAlgorithms.ProcessConversationMetadata(conversation)
					-- Update root metadata of the conversation with the presence of errors
					mConversations.AddRootMetadataToConversation(pinfo, {
						has_errors = conversation_has_errors
					})
				end
			end
		end

		--------------
		-- Features --
		--------------

		-- Associated messages
		if not blocking_errors then
			errors, blocking_errors = mFeatureAssociatedMessages.AddFieldsToSubtree(buffer, subtree, pinfo, errors)
		end

		-- Conversations
		if not blocking_errors then
			errors, blocking_errors = mfeatureConversations.AddFieldsToSubtree(buffer, subtree, pinfo, errors)
		end

		-- Timing feature
		if not blocking_errors then
			errors, blocking_errors = mFeatureTiming.AddFieldsToSubtree(buffer, subtree, pinfo, errors)
		end

		-- Retry commands
		if not blocking_errors then
			errors, blocking_errors = mfeatureRetryCommands.AddFieldsToSubtree(buffer, subtree, pinfo, errors)
		end

		-----------------
		-- Plugin Info --
		-----------------

		-- Add the Has Errors field to the subtree
		local has_errors = #errors > 0
		mHeaders.SetHasErrorsField(has_errors, subtree)

		-- DEBUG
		-- for _,err in pairs(errors) do print(pinfo.number, err) end

		-- Add plugin information to the subtree
		subtree:add("AECP Diagnostics plugin version " .. mPluginInfo.GetVersion())
			--- Mark as a generated field (with data inferred but not contained in the packet)
			:set_generated(true)

	end

	-----------------
	-- Plugin Info --
	-----------------

	-- Register plugin information into Wireshark
	mPluginInfo.RegisterPluginInfo()

end

-- Finally, register protocol as a postdissector
-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_fn_register_postdissector_proto___allfields__
register_postdissector(mProto.Proto)
