---
--- ieee17221_specs.lua
---
--- Holds fields belonging to the IEEE 1722.1 protocol
---

-- Init module object
local m = {}

---------------------
-- Private Members --
---------------------

-- Private list of Field objects
m._fields = {}

-- List of IEEE 1722.1 Wireshark field names
m._FIELD_NAMES = {
    CONTROL_DATA_LENGTH       = "ieee17221.control_data_length",
    MESSAGE_TYPE              = "ieee17221.message_type",
    VENDOR_UNIQUE_PROTOCOL_ID = "ieee17221.protocol_id",
}

--------------------
-- Public Methods --
--------------------

--- Load all IEEE 1722.1 fields to internal memory for future access using getter methods
--- Must be called before the protocol's dissector gets called
function m.LoadAllFields()
    m._GetField(m._FIELD_NAMES.CONTROL_DATA_LENGTH)
    m._GetField(m._FIELD_NAMES.MESSAGE_TYPE)
    m._GetField(m._FIELD_NAMES.VENDOR_UNIQUE_PROTOCOL_ID)
end

--- Read the value of Control Data Length field
--- @return number|nil control_data_length
function m.GetControldataLength()
    -- Get field
    local field = m._GetField(m._FIELD_NAMES.CONTROL_DATA_LENGTH)
    -- If field exists
    if field ~= nil then
        -- Read field info
        local field_info = field()
        -- If field_info exists and has the expected type
        if field_info ~= nil and field_info.type == ftypes.UINT16 then
            -- Return the field value
            return field_info.value
        end
    end
    -- Field not found
    error("Field not found: '" .. m._FIELD_NAMES.CONTROL_DATA_LENGTH .. "'")
end

--- Read the value of Message Type field
--- @return number|nil message_type
function m.GetMessageType()
    -- Get field
    local field = m._GetField(m._FIELD_NAMES.MESSAGE_TYPE)
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
    -- Field not found
    error("Field not found: '" .. m._FIELD_NAMES.MESSAGE_TYPE .. "'")
end

--- Read the value or Vendor Unique Procol ID as an hexadecimal string
--- @return string vendor_unique_protocol_id
function m.GetVendorUniqueProtocolIdHexString()
    -- Get field
    local field = m._GetField(m._FIELD_NAMES.VENDOR_UNIQUE_PROTOCOL_ID)
    -- If field exists
    if field ~= nil then
        -- Read field info
        local field_info = field()
        -- If field_info has the expected type
        if field_info ~= nil and field_info.type == ftypes.UINT48 then
            -- Return the field value converted to lower case hex string
            return field_info.range:bytes():tohex(true)
        end
    end
    -- Field not found
    error("Field not found: '" .. m._FIELD_NAMES.VENDOR_UNIQUE_PROTOCOL_ID .. "'")
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
