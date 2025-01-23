---
--- mvu_feature_clock_reference_info.lua
---
--- Handle fields related to GET_CLOCK_REFERENCE_INFO/SET_CLOCK_REFERENCE_INFO commands/responses
---

-- Require dependency modules
local mFields = require("mvu_fields")
local mSpecs = require("mvu_specs")
local mHeaders = require("mvu_headers")
local mIEEE17221Specs = require("ieee17221_specs")
local mIEEE17221Fields = require("ieee17221_fields")

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

--------------------
-- Public Methods --
--------------------

--- Declare all fields of this feature
function m.DeclareFields()

	------------
	-- FIELDS --
	------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField

	-- Clock domain index
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO command
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields["mvu.clock_domain_index"]
	= mFields.CreateField(
		ProtoField.uint16("mvu.clock_domain_index", "Clock Domain Index", base.DEC)
	)

	-- Flags for Media Clock fields validity
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields["mvu.media_clock_flags"]
	= mFields.CreateField(
		ProtoField.uint32("mvu.media_clock_flags", "Media Clock Flags", base.HEX)
	)

	-- Media clock referency priority field validity
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields["mvu.media_clock.reference_priority_valid"]
	= mFields.CreateField(
		ProtoField.bool(
			"mvu.media_clock.reference_priority_valid",
			"REFERENCE PRIORITY VALID",
			8,    -- parent bitfield size
			nil,  -- table of value strings
			0x01) -- bit mask for this field
	)

	-- Media clock domain name field validity
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields["mvu.media_clock.domain_name_valid"]
	= mFields.CreateField(
		ProtoField.bool(
			"mvu.media_clock.domain_name_valid",
			"DOMAIN NAME VALID",
			8,    -- parent bitfield size
			nil,  -- table of value strings
			0x02) -- bit mask for this field
	)

	-- Default media clock reference priority
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields["mvu.default_mcr_prio"]
	= mFields.CreateField(
		ProtoField.uint8("mvu.default_mcr_prio", "Default Media Clock Reference Priority", base.DEC)
	)

	-- User media clock reference priority
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields["mvu.user_mcr_prio"]
	= mFields.CreateField(
		ProtoField.uint8("mvu.user_mcr_prio", "User Media Clock Reference Priority", base.DEC)
	)

	-- Media clock domain name
	--   Expected in:
	--     GET_MEDIA_CLOCK_REFERENCE_INFO response
	--     SET_MEDIA_CLOCK_REFERENCE_INFO command
	--     SET_MEDIA_CLOCK_REFERENCE_INFO response
	m._fields["mvu.media_clock.domain_name"]
	= mFields.CreateField(
		ProtoField.string("mvu.media_clock.domain_name", "Media Clock Domain Name", base.UNICODE)
	)

	-- -- System unique ID
	-- m._fields["mvu.system_unique_id"]
	-- = mFields.CreateField(
	-- 	ProtoField.uint32("mvu.system_unique_id", "System Unique ID", base.HEX)
	-- )

	-------------------
	-- EXPERT FIELDS --
	-------------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoExpert

end

--- Add fields to the subtree
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @return table<string> errors List of errors encountered
function m.AddFieldsToSubtree(buffer, subtree)

	-- Init list of errors
	local errors = {}

	-- Read IEEE 1722.1 field values
	local message_type = mIEEE17221Fields.GetMessageType()

	-- Read MVU header field values
	local command_type = mHeaders.GetCommandType()

	-- Get MVU payload bytes from buffer
	local mvu_payload_bytes, mvu_payload_start = mHeaders.GetMvuPayload()

	-- If the message is one of these:
	--   GET_MEDIA_CLOCK_REFERENCE_INFO command
	--   SET_MEDIA_CLOCK_REFERENCE_INFO command
	if command_type == mSpecs.COMMAND_TYPES.GET_MEDIA_CLOCK_REFERENCE_INFO
	or command_type == mSpecs.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO
	then

		----------------------------------
		-- Validate Control Data Length --
		----------------------------------

		-- Read Control data Length
		local control_data_length = mIEEE17221Fields.GetControldataLength()

		-- If the control data length is smaller than expected
		local expected_control_data_length = 20
		if control_data_length < expected_control_data_length then

			-- Build eror message
			local error_message = "Control Data Length value is too small for this command"
				.. " (CDL = " .. control_data_length
				.. ", expected: " .. expected_control_data_length .. ")"

			-- Get control data length error expert field from headers
			local f_control_data_length_errors = mFields.GetExpertField("mvu.expert.control_data_length_error")

			-- If expert field was found
			if f_control_data_length_errors ~= nil then
				-- Add control data length error to the subtree
				subtree:add_tvb_expert_info(f_control_data_length_errors, buffer(16, 2), error_message)
			end

			-- Add error
			table.insert(errors, error_message)

			-- Do no more dissecting, stop function here
			return errors

		end

		----------------------------
		-- Add fields to the tree --
		----------------------------

		--
		-- Clock domain index
		--

		-- Get clock domain index
		local clock_domain_index = mvu_payload_bytes:int(2, 2)

		-- Write clock domain index to the MVU subtree
		subtree:add(m._fields["mvu.clock_domain_index"], buffer(mvu_payload_start + 2, 2), clock_domain_index)
	end

	-- If the message is one of these:
	--   SET_MEDIA_CLOCK_REFERENCE_INFO command
	--   SET_MEDIA_CLOCK_REFERENCE_INFO response
	--   GET_MEDIA_CLOCK_REFERENCE_INFO response
	if (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_COMMAND and command_type == mSpecs.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO)
	or (message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE and
		(command_type == mSpecs.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO or command_type == mSpecs.COMMAND_TYPES.GET_MEDIA_CLOCK_REFERENCE_INFO))
	then

		----------------------------------
		-- Validate Control Data Length --
		----------------------------------

		-- Read Control data Length
		local control_data_length = mIEEE17221Fields.GetControldataLength()

		-- If the control data length is smaller than expected
		local expected_control_data_length = 92
		if control_data_length < expected_control_data_length then

			-- Build eror message
			local error_message = "Control Data Length value is too small for this command"
				.. " (CDL = " .. control_data_length
				.. ", expected: " .. expected_control_data_length .. ")"

			-- Get control data length error expert field from headers
			local f_control_data_length_errors = mFields.GetExpertField("mvu.expert.control_data_length_error")

			-- If expert field was found
			if f_control_data_length_errors ~= nil then
				-- Add control data length error to the subtree
				subtree:add_tvb_expert_info(f_control_data_length_errors, buffer(16, 2), error_message)
			end

			-- Add error
			table.insert(errors, error_message)

			-- Do no more dissecting, stop function here
			return errors

		end

		----------------------------
		-- Add fields to the tree --
		----------------------------

		--
		-- Media clock reference info flags
		--

		-- Get media clock reference info flags
		local media_clock_reference_info_flags = mvu_payload_bytes:int(4, 1)

		-- Write media clock reference info flags to the MVU subtree
		subtree:add(m._fields["mvu.media_clock_flags"], buffer(mvu_payload_start + 4, 1), media_clock_reference_info_flags)

		-- Write individual media clock reference info flags to the MVU subtree
		subtree:add(m._fields["mvu.media_clock.reference_priority_valid"], buffer(mvu_payload_start + 4, 1))
		subtree:add(m._fields["mvu.media_clock.domain_name_valid"], buffer(mvu_payload_start + 4, 1))

		--
		-- Default media clock reference priority
		--

		-- Get default media clock reference priority
		local default_media_clock_reference_priority = mvu_payload_bytes:uint(6, 1)

		-- Write default media clock reference priority to the MVY subtree
		subtree:add(m._fields["mvu.default_mcr_prio"], buffer(mvu_payload_start + 6, 1), default_media_clock_reference_priority)

		--
		-- User media clock reference priority
		--

		-- Get user media clock reference priority
		local user_media_clock_reference_priority = mvu_payload_bytes:uint(7, 1)

		-- Write user media clock reference priority to the MVY subtree
		subtree:add(m._fields["mvu.user_mcr_prio"], buffer(mvu_payload_start + 7, 1), user_media_clock_reference_priority)

		--
		-- Media clock domain name
		--

		-- Get media clock domain name
		local media_clock_domain_name = buffer(mvu_payload_start + 12, 64):raw()

		-- Determine media clock domain name string length
		local null_character_position = media_clock_domain_name:find("\0")
		local media_clock_domain_name_length = null_character_position ~= nil and (null_character_position - 1) or 64

		-- Write media clock domain name to the MVU subtree
		subtree:add(m._fields["mvu.media_clock.domain_name"], buffer(mvu_payload_start + 12, media_clock_domain_name_length), media_clock_domain_name)

	end

	-- Return errors
	return errors

end

-- Return module object
return m
