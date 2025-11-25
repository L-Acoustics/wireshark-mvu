--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Handle fields related to retry commands
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

------------------------
-- Feature Parameters --
------------------------

-- Minimum time interval before a retry command
m.COMMAND_RETRY_INTERVAL_SECONDS = 0.250

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

-- List of fields related to GET_MILAN_INFO commands/responses
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_ABBRS = {
    IS_RETRY_COMMAND            = "aecp_diagnostics.is_retry_command",
    IS_UNEXPECTED_RETRY_COMMAND = "aecp_diagnostics.expert.is_unexpected_retry_command",
    HAS_MISSING_RETRY_COMMAND   = "aecp_diagnostics.expert.has_missing_retry_command",
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

	-- Is Retry Command
	local field_name = "Is Retry Command"
	local field_abbr = m._FIELD_ABBRS.IS_RETRY_COMMAND
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

	-- Is unexpected retry error
	local field_name = "Is unexpected retry error"
	local field_abbr = m._FIELD_ABBRS.IS_UNEXPECTED_RETRY_COMMAND
	local unexpected_response_error = ProtoExpert.new(field_abbr, field_name, expert.group.PROTOCOL, expert.severity.ERROR)
	m._experts[field_abbr] = mFields.CreateExpertField(field_abbr, unexpected_response_error)

	-- Has missing retry command error
	local field_name = "Has missing retry command error"
	local field_abbr = m._FIELD_ABBRS.HAS_MISSING_RETRY_COMMAND
	local unexpected_response_error = ProtoExpert.new(field_abbr, field_name, expert.group.PROTOCOL, expert.severity.ERROR)
	m._experts[field_abbr] = mFields.CreateExpertField(field_abbr, unexpected_response_error)

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
		-- AECP or VENDOR UNIQUE command
		--

		if mIEEE17221Specs.IsAecpCommand(message_type) then

			--
			-- Is Retry command
			--

			-- Check if the command is a retry command
			local is_retry_command = (message_in_conversation.metadata.is_retry_command == true)

			-- Add field to subtree
			subtree:add(m._fields[m._FIELD_ABBRS.IS_RETRY_COMMAND], is_retry_command)

			--
			-- Is unexpected Retry command
			--

			if message_in_conversation.metadata.is_unexpected_retry_command then
				-- Build error message
				local error_message = "Command is unexpected retry command"
				if type(message_in_conversation.metadata.is_unexpected_retry_command_message)=="string" then
					error_message = error_message .. ": "..message_in_conversation.metadata.is_unexpected_retry_command_message
				end
				-- Add late response error
				subtree:add_tvb_expert_info(m._experts[m._FIELD_ABBRS.IS_UNEXPECTED_RETRY_COMMAND], error_message)
				-- Add error message to errors list
				table.insert(errors, error_message)
			end

			--
			-- Has missing retry command
			--

			if message_in_conversation.metadata.has_missing_retry_command then
				-- Build error message
				local error_message = "Command should has been repeated as retry command"
				-- Add late response error
				subtree:add_tvb_expert_info(m._experts[m._FIELD_ABBRS.HAS_MISSING_RETRY_COMMAND], error_message)
				-- Add error message to errors list
				table.insert(errors, error_message)
			end

		end
	end

	-- Return non-blocking errors
	return errors

end

-- Return module object
return m
