---
--- mvu_fields.lua
---
--- Contains the MVU Wireshark protocol fields
---

-- Require dependencies
local mProto = require("mvu_proto")

-- Init the module object to return
local m = {}

---------------------
-- Private Members --
---------------------

-- Private list of Field objects
m._fields = {}

--------------------
-- Public Methods --
--------------------

--- Create a Field object for the protocol.
--- Add the field to internal list only the first time it is created (discriminate with the field's 'name' property)
--- When attempting to create again, discard the passed field argument and return existing field object.
--- @param field_object any
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

--- Register all requested MVU fields into the protocol
function m.RegisterAllFieldsInProtocol()
    -- Init fields list
    local fields = {}
    -- Copy all requested internal fields to fields table
    for _, field in pairs(m._fields) do
        table.insert(fields, field)
    end
    -- Register fields
    -- See documentation https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_attrib_proto_fields
    mProto.Proto.fields = fields
end

-- Return the module object
return m
