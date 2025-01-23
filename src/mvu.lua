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
local mControl = require("mvu_control")
local mMilanInfo = require("mvu_feature_milan_info")
local mSystemUniqueId = require("mvu_feature_system_unique_id")
local mClockreferenceInfo = require("mvu_feature_clock_reference_info")

-- Check compatibility with Wireshark version
if not mControl.IsWiresharkVersionCompatible() then
	-- Report incompatibility of plugin to user
	local incompatibility_message =
		"The MVU plugin (mvu.lua) requires Wireshark version ".. mControl.GetMinimumWiresharkVersion()  .." or newer." .. "\n"
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

		-- Read MVU payload and positions
		mHeaders.ReadMvuPayloadAndPosition(buffer)

		-- Add header fields to subtree
		errors = mHeaders.AddHeaderFieldsToSubtree(buffer, mvuSubtree)

		--------------
		-- Features --
		--------------

		-- Add Milan Info fields to subtree
		if #errors == 0 then
			errors = mMilanInfo.AddFieldsToSubtree(buffer, mvuSubtree)
		end

		-- Add System Unique Id fields to subtree
		if #errors == 0 then
			error = mSystemUniqueId.AddFieldsToSubtree(buffer, mvuSubtree)
		end

		-- Add Clock Reference Info fields to subtree
		if #errors == 0 then
			errors = mClockreferenceInfo.AddFieldsToSubtree(buffer, mvuSubtree)
		end

		-----------------
		-- Packet Info --
		-----------------

		-- Write to packet info columns
		mHeaders.WritePacketInfo(pinfo, errors)

		-----------------
		-- Plugin Info --
		-----------------

		-- Register plugin informatino into Wireshark
		mPluginInfo.RegisterPluginInfo()

		-- Add plugin information to the subtree
		mvuSubtree:add("[MVU plugin version: " .. mPluginInfo.GetVersion() .. "]")
		mvuSubtree:add("[Based on Milan Specifications version: " .. mSpecs.SPEC_VERSION .. "]")

	end

end

-- Finally, register protocol as a postdissector
-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_fn_register_postdissector_proto___allfields__
register_postdissector(mProto.Proto)
