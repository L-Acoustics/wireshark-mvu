---
--- mvu.lua
---
--- Milan Vendor Unique plugin for Wireshark
---
--- Declares and implements 'mvu' protocol for displaying information related
--- to Milan Vendor Unique data in IEEE 1722.1 packets

-- Require dependency modules
local mPluginInfo = require("mvu_plugin_info")
local mProto = require("mvu_proto")
local mFields = require("mvu_fields")
local mSpecs = require("mvu_specs")
local mHeaders = require("mvu_headers")
local mIEEE17221Fields = require("ieee17221_fields")
local mControl = require("control")
local mMilanInfo = require("mvu_feature_milan_info")
local mSystemUniqueId = require("mvu_feature_system_unique_id")
local mClockreferenceInfo = require("mvu_feature_clock_reference_info")
local mHelpers = require("helpers")

-- Load IEEE 1722.1 fields needed for dissecting MVU packets
mIEEE17221Fields.LoadAllFields()

-- Declare MVU fields
mHeaders.DeclareFields()
mMilanInfo.DeclareFields()
mSystemUniqueId.DeclareFields()
mClockreferenceInfo.DeclareFields()

-- Register declared fields to protocol
mFields.RegisterAllFieldsInProtocol()

--------------------
-- IMPLEMENTATION --
--------------------

--- Implementation of protocol's dissector
--- @see documentation https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_attrib_proto_dissector
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param pinfo table The packet info (PInfo object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
--- @param tree table The tree on which to add the procotol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function mProto.Proto.dissector(buffer, pinfo, tree)

	-- If we are dissecting a MVU packet and the packet is visited
	if mControl.IsMvuPacket() and pinfo.visited then

		-- Init table of errors that we may encounter during dissecting
		local errors = {}

		-------------
		-- Headers --
		-------------

		-- Add MVU subtree to packet details
		local mvuSubtree = mHeaders.CreateMvuSubtree(buffer, tree)

		-- Add header fields to subtree
		if #errors == 0 then
			errors = mHelpers.MergeTables(errors, mHeaders.AddHeaderFieldsToSubtree(buffer, mvuSubtree))
		end

		--------------
		-- Features --
		--------------

		-- Add Milan Info fields to subtree
		if #errors == 0 then
			mMilanInfo.AddFieldsToSubtree(buffer, mvuSubtree)
		end

		-- Add System Unique Id fields to subtree
		if #errors == 0 then
			mSystemUniqueId.AddFieldsToSubtree(buffer, mvuSubtree)
		end

		-- Add Clock Reference Info fields to subtree
		if #errors == 0 then
			mClockreferenceInfo.AddFieldsToSubtree(buffer, mvuSubtree)
		end

		-- Add plugin information to the subtree
		mvuSubtree:add("[Dissector version: " .. mPluginInfo.VERSION .. "]")
		mvuSubtree:add("[Based on Milan Specifications version: " .. mSpecs.SPEC_VERSION .. "]")

		-----------------
		-- Packet Info --
		-----------------
		mHeaders.WritePacketInfo(pinfo, errors)

	end

end

-- Finally, register protocol as a postdissector
-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_fn_register_postdissector_proto___allfields__
register_postdissector(mProto.Proto)
