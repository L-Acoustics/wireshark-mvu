---
--- mvu_feature_milan_info.lua
---
--- Handle fields related to GET_MILAN_INFO commands
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
	m._fields["mvu.protocol_version"]                = mFields.CreateField(ProtoField.uint32 ("mvu.protocol_version",                "Protocol Version",                      base.DEC))
	m._fields["mvu.feature_flags"]                   = mFields.CreateField(ProtoField.uint32 ("mvu.feature_flags",                   "Feature Flags",                         base.HEX))
	m._fields["mvu.feature.redundancy"]              = mFields.CreateField(ProtoField.bool   ("mvu.feature.redundancy",              "REDUNDANCY",                            32, nil, 0x00000001))
	m._fields["mvu.feature.talker_dynamic_mappings"] = mFields.CreateField(ProtoField.bool   ("mvu.feature.talker_dynamic_mappings", "TALKER_DYNAMIC_MAPPINGS_WHILE_RUNNING", 32, nil, 0x00000002))
end

--- Add fields to the subtree
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param subtree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function m.AddFieldsToSubtree(buffer, subtree)

	-- Read IEEE 1722.1 field values
	local message_type        = mIEEE17221Fields.GetMessageType()

	-- Read MVU header field values
	local command_type = mHeaders.GetCommandType()

	-- If the message is a reponse to GET_MILAN_INFO
	if 	message_type == mIEEE17221Specs.AECP_MESSAGE_TYPES.VENDOR_UNIQUE_RESPONSE
	and command_type == mSpecs.COMMAND_TYPES.GET_MILAN_INFO
	then

		-- Get MVU payload bytes from buffer
		local mvu_payload_bytes, mvu_payload_start = mHeaders.GetMvuPayloadBytes()

		-- Read protocol version (4 bytes)
		local protocol_version = mvu_payload_bytes:int(4, 4)

		-- Write protocol version to the MVU subtree
		subtree:add(m._fields["mvu.protocol_version"], buffer(mvu_payload_start + 4, 4), protocol_version)

		-- Read feature flags
		local feature_flags = mvu_payload_bytes:int(8, 4)

		-- Write feature flags to the MVU subtree
		subtree:add(m._fields["mvu.feature_flags"], buffer(mvu_payload_start + 8, 4), feature_flags)

		-- Write individual features flags to the MVU subtree
		subtree:add(m._fields["mvu.feature.talker_dynamic_mappings"], buffer(mvu_payload_start + 8, 4))
		subtree:add(m._fields["mvu.feature.redundancy"], buffer(mvu_payload_start + 8, 4))

	end

end

-- Return module object
return m
