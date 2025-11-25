--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Handle fields related to command/response association
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
local mIEEE17221Specs  = require("ieee17221_specs")
local mIEEE17221Fields = require("ieee17221_fields")
local mConversations   = require("aecp-diagnostics_conversations")

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
	COMMAND   = "aecp_diagnostics.command",
	RESPONSE  = "aecp_diagnostics.response",
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

	-- Command frame number (clickable link in Wireshark packet details)
	local field_name = "Command"
	local field_abbr = m._FIELD_ABBRS.COMMAND
	m._fields[field_abbr]
	= mFields.CreateField(
		ProtoField.framenum(
			field_abbr,
			field_name
		)
	)

	-- Response frame number (clickable link in Wireshark packet details)
	local field_name = "Response"
	local field_abbr = m._FIELD_ABBRS.RESPONSE
	m._fields[field_abbr]
	= mFields.CreateField(
		ProtoField.framenum(
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
	local message_type     = mIEEE17221Fields.GetMessageType()
	local unsolicited_flag = mIEEE17221Fields.GetUnsolicitedFlag()

	-- Ignore unsolicited messages
	if unsolicited_flag == true then
		return errors
	end

	-- On second visit
	if pinfo.visited then

		-- Get conversation
		local conversation = mConversations.GetCurrentConversationMessages(pinfo)
		if type(conversation)~="table" then
			table.insert(errors, "Conversation not found")
			return errors, true
		end

		-- Find message in conversation
		local message_in_conversation = nil
		for _,v in pairs(conversation) do
			if v.metadata.frame_number == pinfo.number then
				message_in_conversation = v
				break
			end
		end
		if type(message_in_conversation)~="table" then
			table.insert(errors, "Message not found in conversation")
			return errors, true
		end

		----------------------------
		-- Add fields to the tree --
		----------------------------

		--
		-- AECP or VENDOR UNIQUE response
		--

		if mIEEE17221Specs.IsAecpResponse(message_type) then

			--
			-- Command frame number
			--

			-- If the response has an associated command
			local command_frame_number = message_in_conversation.metadata.associated_command_frame_number
			if type(command_frame_number)=="number" then
				-- Add field to subtree
				subtree:add(m._fields[m._FIELD_ABBRS.COMMAND], command_frame_number)
			end
		end

		--
		-- AECP or VENDOR UNIQUE command
		--

		if mIEEE17221Specs.IsAecpCommand(message_type) then

			--
			-- Response frame number
			--

			-- If the command has an associated response
			local response_frame_number = message_in_conversation.metadata.associated_response_frame_number
			if type(response_frame_number)=="number" then
				-- Add field to subtree
				subtree:add(m._fields[m._FIELD_ABBRS.RESPONSE], response_frame_number)
			end
		end
	end

	-- Return non-blocking errors
	return errors

end

-- Return module object
return m
