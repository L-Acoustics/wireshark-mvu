--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Handle fields related to conversations
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
local mFields          = require("aecp-diagnostics_fields")
local mIEEE17221Fields = require("ieee17221_fields")
local mConversations   = require("aecp-diagnostics_conversations")
local mHelpers         = require("helpers")

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

-- List of fields related to GET_MILAN_INFO commands/responses
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_ABBRS = {
	CONVERSATION = "aecp_diagnostics.conversation",
	HAS_ERRORS   = "aecp_diagnostics.conversation_has_errors",
}

-- Internal list of expert fields
m._experts = {}

--------------------
-- Public Methods --
--------------------

--- Declare all fields of this feature
function m.DeclareFields()

	------------
	-- FIELDS --
	------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField

	-- Conversation index
	local field_name = "AECP Conversation"
	local field_abbr = m._FIELD_ABBRS.CONVERSATION
	m._fields[field_abbr]
	= mFields.CreateField(
		ProtoField.uint32(
			field_abbr,
			field_name
		)
	)

	-- Conversation has errors
	local field_name = "AECP Conversation has errors"
	local field_abbr = m._FIELD_ABBRS.HAS_ERRORS
	m._fields[field_abbr]
	= mFields.CreateField(
		ProtoField.bool(
			field_abbr,
			field_name
		)
	)

	-------------------
	-- EXPERT FIELDS --
	-------------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoExpert

end

--- Add fields to the subtree
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @param pinfo any Packet info (Pinfo object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
--- @param errors table<string> Existing errors
--- @return table<string> errors Amended list of errors
--- @return boolean|nil blocking_errors Indicates if one of the returned errors is blocking and should interrupt further packet analysis
function m.AddFieldsToSubtree(buffer, subtree, pinfo, errors)

	-- Read protocol information
	local unsolicited_flag = mIEEE17221Fields.GetUnsolicitedFlag()

	-- Ignore unsolicited messages
	if unsolicited_flag == true then
		return errors
	end

	-- On second visit
	if pinfo.visited then

		----------------------------
		-- Add fields to the tree --
		----------------------------

		--
		-- Conversation index
		--

		-- Get conversation
		local conversation_index = mConversations.GetCurrentConversationOccurrenceAbsoluteIndex(pinfo)
		if type(conversation_index)=="number" then
			-- Add field to subtree
			subtree:add(m._fields[m._FIELD_ABBRS.CONVERSATION], conversation_index)
		end

		--
		-- Conversation has errors
		--

		-- Get conversation metadata
		local conversation_root_metadata = mConversations.GetCurrentConversationRootMetadata(pinfo)
		if type(conversation_root_metadata)=="table" and conversation_root_metadata.has_errors then
			-- Add field to subtree
			subtree:add(m._fields[m._FIELD_ABBRS.HAS_ERRORS], true)
		end

	end

	-- Return non-blocking errors
	return errors

end

-- Return module object
return m
