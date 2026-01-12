--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Handles protocol fields extracted from MVU headers
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
local mProto = require("aecp-diagnostics_proto")
local mFields = require("aecp-diagnostics_fields")
local mConversations = require("aecp-diagnostics_conversations")

-- Init the module object to return
local m = {}

---------------------
-- Private Members --
---------------------

-- Internal list of fields
m._fields = {}

-- List of Wireshark field names related to MVU headers
-- These field names can be used in Wireshark display filters to analyze MVU packets
m._FIELD_NAMES = {
    HAS_ERRORS = "aecp_diagnostics.has_errors",
}

-- Internal list of expert fields
m._experts = {}

-- The subtree
m._subtree = nil

--------------------
-- Public Methods --
--------------------

--- Declare all fields of this feature
function m.DeclareFields()

	------------
	-- FIELDS --
	------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField

	-- Flag for when the packet has errors
	m._fields[m._FIELD_NAMES.HAS_ERRORS]
	= mFields.CreateField(
		ProtoField.bool(m._FIELD_NAMES.HAS_ERRORS)
	)

	-------------------
	-- EXPERT FIELDS --
	-------------------
	-- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoExpert

end

--- Create the packet description subtree for AECP Diagnostics
--- @param buffer any The buffer to dissect (TVB object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
--- @param tree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
--- @return table subtree
function m.CreateAecpDiagnosticsSubtree(buffer, tree)

		-- Add AECP Diagnostics subtree to packet details
		m._subtree = tree:add(mProto.Proto, buffer)

		-- Return the subtree
		return m._subtree
end

--- Set the value of the Has Errors field and add to subtree
--- @param has_errors boolean
--- @param subtree table The tree on which to add the protocol items (TreeItem object, see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function m.SetHasErrorsField(has_errors, subtree)
	if (has_errors) then
		-- Add Has Errors field to the subtree
		subtree:add(m._fields[m._FIELD_NAMES.HAS_ERRORS], true, "The packet has errors!")
			--- Mark as a generated field (with data inferred but not contained in the packet)
			:set_generated(true)
	end
end

-- Return the module object
return m
