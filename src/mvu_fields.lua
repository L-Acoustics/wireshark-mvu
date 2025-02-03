--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Gathers and registers the MVU Wireshark protocol fields
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

-- Require dependencies
local mProto = require("mvu_proto")

-- Init the module object to return
local m = {}

---------------------
-- Private Members --
---------------------

-- Private list of Field objects
m._fields = {}

-- Private list of expert fields
m._experts = {}

--------------------
-- Public Methods --
--------------------

--- Create a Field object for the protocol.
--- Add the field to internal list only the first time it is created (discriminate with the field's 'name' property)
--- When attempting to create again, discard the passed field argument and return existing field object.
--- @param field_object any
--- @return any field
function m.CreateField(field_object)

    -- If the field object is not of type "userdata"
    if type(field_object) ~= "userdata" then
        error("CreateField() argument #1: incorrect data type, 'userdata' expected")
        return
    end

    -- If the field object does not have a "abbr" property
    if (type(field_object.abbr) ~= "string") then
        error("CreateField() argument #1: incorrect data type, '.abbr' property expected")
        return
    end

    -- If the field does not exist yet in the list
    if m._fields[field_object.abbr] == nil then
        -- Create and add new Field object to the list
        m._fields[field_object.abbr] = field_object
    end

    -- Return the existing or created field
    return m._fields[field_object.abbr]

end

--- Create a ProtoExpert object for the protocol.
--- Add the field to internal list only the first time it is created (discriminate with the field's 'name' property)
--- When attempting to create again, discard the passed field argument and return existing field object.
--- @param abbr string
--- @param expert userdata
--- @return any expert
function m.CreateExpertField(abbr, expert)

    -- If the field object is not of type "userdata"
    if type(expert) ~= "userdata" then
        error("CreateField() argument #1: incorrect data type, 'userdata' expected")
        return
    end

    -- If the field does not exist yet in the list
    if m._experts[abbr] == nil then
        -- Create and add new Field object to the list
        m._experts[abbr] = expert
    end

    -- Return the existing or created field
    return m._experts[abbr]

end

--- Get a field by its abbreviated name
--- @param abbr string abbreviated field name
--- @return any|nil expert_field
function m.GetField(abbr)
    -- If the field exists in the list
    if m._fields[abbr] ~= nil then
        -- Return the field
		return m._fields[abbr]
    end
end

--- Get an expert field by its abbreviated name
--- @param abbr string abbreviated expert field name
--- @return any|nil expert_field
function m.GetExpertField(abbr)
    -- If the expert field exists in the list
    if m._experts[abbr] ~= nil then
        -- Return the expert field
		return m._experts[abbr]
    end
end

--- Register all requested MVU fields into the protocol
--- Must be called after all fields have been created using CreateField() and CreateExpertField()
function m.RegisterAllFieldsInProtocol()

    -- Register fields
    -- See documentation https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_attrib_proto_fields
    mProto.Proto.fields = m._fields

    -- Register expert
    -- See documentation https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_attrib_proto_experts
    mProto.Proto.experts = m._experts

end

-- Return the module object
return m
