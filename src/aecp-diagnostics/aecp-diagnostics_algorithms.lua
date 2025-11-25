--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Functions implementing various algorithms used by the plugin
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
local mIEEE17221Specs        = require("ieee17221_specs")
local mMvuSpecs              = require("mvu_specs")
local mFeatureTiming         = require("aecp-diagnostics_feature_timing")
local mfeatureRetryCommands  = require("aecp-diagnostics_feature_retry-commands")
local mHelpers               = require("helpers")

-- Init the module object to return
local m = {}

----------------------
-- Public Functions --
----------------------

--- Process conversation metadata
--- @param conversation table
--- @return boolean conversation_has_errors
function m.ProcessConversationMetadata(conversation)

	-- Constants
	local COMMAND_RETRY_INTERVAL_SECONDS    = mfeatureRetryCommands.COMMAND_RETRY_INTERVAL_SECONDS
	local RESPONSE_TIMEOUT_DURATION_SECONDS = mFeatureTiming.RESPONSE_TIMEOUT_DURATION_SECONDS

	-- Helper functions

	--- Determines if the message type is that of a command
	--- @param message table
	--- @return boolean result
	local function IsCommand(message)
		return mIEEE17221Specs.IsAecpCommand(message.type)
	end

	--- Determines if the message type is that of a response
	--- @param message table
	--- @return boolean result
	local function IsResponse(message)
		return mIEEE17221Specs.IsAecpResponse(message.type)
	end

	--- Determines if the message is en AEM message
	--- @param message table
	--- @return boolean result
	local function IsAemMessage(message)
		return mIEEE17221Specs.IsAemMessage(message.type)
	end

	--- Determines if the message is a MVU message
	--- @param message table
	--- @return boolean result
	local function IsMvuMessage(message)
		return mMvuSpecs.IsMvuMessage(message.type)
	end

	--- Determines if the message is en AEM message
	--- @param message table
	--- @return boolean result
	local function IsAemMessage(message)
		return mIEEE17221Specs.IsAemMessage(message.type)
	end

	-- Working variables
    local messages = mHelpers.SortTableOfTables(conversation)

	--
	-- Management of errors
	--

	local errors = {}
	--- Set an error by name for a frame number
	--- @param frame_number number
	--- @param error_name string
	--- @param error_message string|nil
	local function SetError(frame_number, error_name, error_message)
		-- Validate variables
		if type(frame_number)~="number" then return end
		if type(error_name)~="string" then return end
		-- Create entry for frame enumber
		if type(errors[frame_number]==nil) then
			errors[frame_number] = {}
		end
		-- Create entry for error
		if type(errors[frame_number][error_name]==nil) then
			errors[frame_number][error_name] = tostring(error_message)
		end
	end

	--- Set an error by name for a frame number
	--- @param frame_number number
	--- @param error_name string
	local function ClearError(frame_number, error_name)
		-- Validate variables
		if type(frame_number)~="number" then return end
		if type(error_name)~="string" then return end
		-- If entry exists for frame number
		if type(errors[frame_number])=="table" then
			-- Remove entry for error
			errors[frame_number][error_name] = nil
		end
	end

	--- Determine if the conversation has at least one error
	--- @return boolean has_errors
	local function HasErrors()
		-- Loop through errors table
		for _,frame_errors in pairs(errors) do
			if type(frame_errors)=="table" then
				for _,_ in pairs(frame_errors) do
					-- Error found!
					return true
				end
			end
		end
		-- Eventually, no errors
		return false
	end

	--
	-- Step 1: Init command and response properties with default value
	--

	for _,message in ipairs(messages) do
		-- Init command properties that shall have a default value
		if IsCommand(message) then
			local command = message
			if command.metadata.is_retry_command            == nil then command.metadata.is_retry_command            = false end
			if command.metadata.is_unexpected_retry_command == nil then command.metadata.is_unexpected_retry_command = false end
		-- Init response properties that shall have a default value
		elseif IsResponse(message) then
			local response = message
			if response.metadata.is_unexpected_response == nil then response.metadata.is_unexpected_response = false end
		end
	end

	--
	-- Step 2: Associate commands and responses
	--

	local consecutive_commands_count = 0
	local consecutive_following_responses_count = 0

	-- Loop through all messages
	for i=1,#messages do
		local message = messages[i]
		-- If the message is a command
		if IsCommand(message) then
			if consecutive_following_responses_count > 0 then
				consecutive_following_responses_count = 0
				consecutive_commands_count = 1
			else
				consecutive_commands_count = consecutive_commands_count + 1
			end
		-- If the message is a response
		elseif IsResponse(message) then
			consecutive_following_responses_count = consecutive_following_responses_count + 1
			local response = message
			-- If this response is the last message of a block of
			-- n commands followed by n responses, with n >= 2
			if  consecutive_commands_count == consecutive_following_responses_count
			and consecutive_commands_count >= 2
			then
				-- Associate these commands and responses 1:1
				for k=1,consecutive_commands_count do
					local response_number = i-(k-1)
					local command_number = response_number - consecutive_commands_count
					local response = messages[response_number]
					local command = messages[command_number]
					command.metadata.associated_response_frame_number = response.metadata.frame_number
					response.metadata.associated_command_frame_number = command.metadata.frame_number
				end
			-- Otherwise
			else
				-- Get previous message
				local previous_message = messages[i-1]
				-- If previous message is a command
				if previous_message ~= nil and IsCommand(previous_message) then
					local previous_command = previous_message
					-- Associate command and response
					previous_command.metadata.associated_response_frame_number = response.metadata.frame_number
					response.metadata.associated_command_frame_number = previous_command.metadata.frame_number
				end
			end
		end
	end

	--
	-- Step 3: Unexpected responses
	--

	for i=1,#messages do
		local message = messages[i]
		-- If the message is a response
		if IsResponse(message) then
			local response = message
			-- If the message has no associated command
			-- and the message is an AEM or MVU message
			if not response.metadata.associated_command_frame_number
			and (IsAemMessage(response) or response.metadata.is_mvu_message)
			then
				-- The response is an unexpected response
				response.metadata.is_unexpected_response = true
				local error_message = "No matching command found for this response"
				response.metadata.is_unexpected_response_message = error_message
				SetError(response.metadata.frame_number, "is_unexpected_response_message", error_message)
			end
		end
	end

	--
	-- Step 4: Command is retry command
	--

	local first_command_passed = false
	for i=1,#messages do
		local message = messages[i]
		-- If the message is a command
		if IsCommand(message) then
			-- If the current command is not the first command in the conversation
			if first_command_passed then
				-- Then this command is a retry command
				local command = message
				command.metadata.is_retry_command = true
			else
				-- We have passed the first command in the conversation
				first_command_passed = true
			end
		end
	end

	--
	-- Step 5: Command is an unexpected retry command
	--

	local command_with_associated_response_in_time_passed = false
	local preceding_command_timestamp = nil
	for i=1,#messages do
		local message = messages[i]
		-- If the message is a command
		if IsCommand(message) then
			local command = message
			-- If it is not the first command to have an associated response
			if command_with_associated_response_in_time_passed then
				-- Then the current command in an unexpected retry command
				command.metadata.is_unexpected_retry_command = true
				local error_message = "A preceding command received a response in time"
				command.metadata.is_unexpected_retry_command_message = error_message
				SetError(command.metadata.frame_number, "is_unexpected_retry_command_message", error_message)
			-- If the current command has an associated response
			elseif command.metadata.associated_response_frame_number then
				-- Find associated response
				for k=1,#messages do
					local message = messages[k]
					if IsResponse(message) then
						local response = message
						if response.metadata.frame_number == command.metadata.associated_response_frame_number then
							local timestamp_difference = response.timestamp - command.timestamp
							-- If the response arrived in time
							if timestamp_difference >= 0 and timestamp_difference <= RESPONSE_TIMEOUT_DURATION_SECONDS then
								-- We have passed the first command with an associated response in time
								command_with_associated_response_in_time_passed = true
								break
							end
						end
					end
				end
			end
			-- If we know the timestamp of the preceding command
			if preceding_command_timestamp then
				-- Compare timestamps
				local timestamp_difference = math.abs(command.timestamp - preceding_command_timestamp)
				-- If the timestamp difference is too low
				if timestamp_difference < COMMAND_RETRY_INTERVAL_SECONDS then
					-- Then the current command in an unexpected retry command
					command.metadata.is_unexpected_retry_command = true
					local error_message = "Unexpected retry time interval: "..timestamp_difference
					command.metadata.is_unexpected_retry_command_message = command.metadata.is_unexpected_retry_command_message or error_message
					SetError(command.metadata.frame_number, "is_unexpected_retry_command_message", error_message)
				end
			end
			-- Update last command timestamp
			preceding_command_timestamp = command.timestamp
		end
	end

	--
	-- Step 6: Command has missing retry
	--

	for i=1,#messages do
		local message = messages[i]
		-- If the message is a command
		if IsCommand(message) then
			local command = message
			-- If the current command has an associated response,
			-- or is an unexpected retry command
			-- then it does not have missing retry
			if command.metadata.associated_response_frame_number
			or command.metadata.is_unexpected_retry_command
			then
				command.metadata.has_missing_retry = false
				ClearError(command.metadata.frame_number, "has_missing_retry")
			-- If the current command has no associated response
			else
				-- If there are no following commands,
				-- then the current command has missing retry
				command.metadata.has_missing_retry = true
				SetError(command.metadata.frame_number, "has_missing_retry")
				-- If there are following commands,
				-- then the current command does not have missing retry
				for k=i+1,#messages do
					local following_message = messages[k]
					if IsCommand(following_message) then
						command.metadata.has_missing_retry = false
						ClearError(command.metadata.frame_number, "has_missing_retry")
						break
					end
				end
			end
		end
	end

	--
	-- Step 7: Response time
	--

	local command_timestamps = {}
	for i=1,#messages do
		local message = messages[i]
		-- If the message is a command
		if IsCommand(message) then
			local command = message
			-- Memorize command timestamp (to avoid parsing the table again)
			command_timestamps[command.metadata.frame_number] = command.timestamp
		end
		-- If the message is a response
		if IsResponse(message) then
			local response = message
			-- If we know the timestamp of the associated command
			if command_timestamps[response.metadata.associated_command_frame_number] then
				-- Calculate the response time
				local command_timestamp = command_timestamps[response.metadata.associated_command_frame_number]
				local response_timestamp = response.timestamp
				local response_time = response_timestamp - command_timestamp
				response.metadata.response_time = response_time

				-- Determine late response error
				if response_time > RESPONSE_TIMEOUT_DURATION_SECONDS then
					SetError(response.metadata.frame_number, "is_late_response")
				end
			end
		end
	end

	-- Return true of the conversaiton has errors
	return HasErrors()

end

-- Return the module object
return m
