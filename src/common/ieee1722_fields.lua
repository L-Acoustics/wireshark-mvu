--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Holds fields belonging to the IEEE 1722 protocol
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

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

-- Private list of Field objects
m._fields = {}

-- List of IEEE 1722.1 Wireshark field names
-- (fields implemented in the existing Wireshark dissector for IEEE 1722.1 protocol)
m._FIELD_NAMES = {
    AVTP_SUBTYPE = "ieee1722.subtype",
}

--------------------
-- Public Methods --
--------------------

--- Load all IEEE 1722 fields to internal memory for future access using getter methods
--- Must be called before the protocol's dissector gets called
function m.LoadAllFields()
    m._GetField(m._FIELD_NAMES.AVTP_SUBTYPE)
end

--- Read the value of AVTP Subtype field
--- @return number|nil message_type
function m.GetAvtpSubtype()
    -- Get field
    local field = m._GetField(m._FIELD_NAMES.AVTP_SUBTYPE)
    -- If field exists
    if field ~= nil then
        -- Read field info
        local field_info = field()
        -- If field_info has the expected type
        if field_info ~= nil and field_info.type == ftypes.UINT8 then
            -- Return the field value
            return field_info.value
        end
    end
end

---------------------
-- Private Methods --
---------------------

--- Get a Field object with the provided name.
--- Create the field object only the first time it is requested.
--- When requested again, get it from internal list.
--- @param field_name string Field name
--- @return userdata field
function m._GetField(field_name)

    -- If the field does not exist yet in the list
    if m._fields[field_name] == nil then
        -- Create and add new Field object to the list
        -- See documentation: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Field.html#lua_fn_Field_new_fieldname_
        m._fields[field_name] = Field.new(field_name)
    end

    -- Return the existing or created field
    return m._fields[field_name]

end

-- Return the module object
return m
