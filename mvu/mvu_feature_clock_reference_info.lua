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
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField
	m._fields["mvu.clock_domain_index"]                   = mFields.CreateField(ProtoField.uint16 ("mvu.clock_domain_index",                   "Clock Domain Index",                     base.DEC))
	m._fields["mvu.media_clock_flags"]                    = mFields.CreateField(ProtoField.uint32 ("mvu.media_clock_flags",                    "Media Clock Flags",                      base.HEX))
	m._fields["mvu.media_clock.reference_priority_valid"] = mFields.CreateField(ProtoField.bool   ("mvu.media_clock.reference_priority_valid", "REFERENCE PRIORITY VALID",               8, nil, 0x01))
	m._fields["mvu.media_clock.domain_name_valid"]        = mFields.CreateField(ProtoField.bool   ("mvu.media_clock.domain_name_valid",        "DOMAIN NAME VALID",                      8, nil, 0x02))
	m._fields["mvu.default_mcr_prio"]                     = mFields.CreateField(ProtoField.uint8  ("mvu.default_mcr_prio",                     "Default Media Clock Reference Priority", base.DEC))
	m._fields["mvu.user_mcr_prio"]                        = mFields.CreateField(ProtoField.uint8  ("mvu.user_mcr_prio",                        "User Media Clock Reference Priority",    base.DEC))
	m._fields["mvu.media_clock.domain_name"]              = mFields.CreateField(ProtoField.stringz("mvu.media_clock.domain_name",              "Media Clock Domain Name",                base.UNICODE))
	m._fields["mvu.system_unique_id"]                     = mFields.CreateField(ProtoField.uint32 ("mvu.system_unique_id", "System Unique ID", base.HEX))
end

--- Add fields to the subtree
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function m.AddFieldsToSubtree(buffer, subtree)

	-- Read IEEE 1722.1 field values
	local message_type = mIEEE17221Fields.GetMessageType()

	-- Read MVU header field values
	local command_type = mHeaders.GetCommandType()

	-- Get MVU payload bytes from buffer
	local mvu_payload_bytes, mvu_payload_start = mHeaders.GetMvuPayloadBytes()

	-- If the message is one of these:
	--   GET_MEDIA_CLOCK_REFERENCE_INFO command
	--   SET_MEDIA_CLOCK_REFERENCE_INFO command
	if command_type == mSpecs.COMMAND_TYPES.GET_MEDIA_CLOCK_REFERENCE_INFO
	or command_type == mSpecs.COMMAND_TYPES.SET_MEDIA_CLOCK_REFERENCE_INFO
	then
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
		-- Get media clock reference info flags
		local media_clock_reference_info_flags = mvu_payload_bytes:int(4, 1)

		-- Write media clock reference info flags to the MVU subtree
		subtree:add(m._fields["mvu.media_clock_flags"], buffer(mvu_payload_start + 4, 1), media_clock_reference_info_flags)

		-- Write individual media clock reference info flags to the MVU subtree
		subtree:add(m._fields["mvu.media_clock.reference_priority_valid"], buffer(mvu_payload_start + 4, 1))
		subtree:add(m._fields["mvu.media_clock.domain_name_valid"], buffer(mvu_payload_start + 4, 1))

		-- Get media clock domain name
		local media_clock_domain_name = mvu_payload_bytes:string(12, 12)

		-- Write media clock domain name to teh MVU subtree
		subtree:add(m._fields["mvu.media_clock.domain_name"], buffer(mvu_payload_start + 12, 12), media_clock_domain_name)
	end

end

-- Return module object
return m
