--[[
	Copyright (c) 2025 by L-Acoustics.

	This file is part of the Milan Vendor Unique plugin for Wireshark
	---
		Global helper functions
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

-- Init the module object to return
local m = {}

--------------------
-- Public Methods --
--------------------

--- Extract table items that have a number key
--- @param t table
--- @return table
function m.GetTableValuesWithNumberKey(t)
	-- Init resulting table
	local result = {}
	-- Loop through input table
	for k,v in pairs(t) do
		if type(k) == "number" then
			result[k] = v
		end
	end
	-- Return resulting table
	return result
end

--- Merge two tables into one
--- @param t1 table|nil First table to merge
--- @param t2 table|nil Second table to merge
--- @return table merged_table
function m.MergeTables(t1, t2)
	-- Init resulting table
	local t = {}
	-- Add all elements of t1
	if type(t1) == "table" then
		for k,v in pairs(t1) do t[k] = v end
	end
	-- Add all elements of t2
	if type(t2) == "table" then
		for k,v in pairs(t2) do t[k] = v end
	end
	-- Return resulting table
	return t
end

--- Compare two string-formatted version numbers (e.g. "5.4.21" or "10.0.0.8")
--- @param v1 string
--- @param v2 string
--- @return number|nil result 0 if versions are equivalent, 1 if v1 newer than v2, -1 if v2 is newer than v1, nil in case of error
function m.CompareVersions(v1, v2)

    -- Split string to arrays of numbers
    local m1 = {}
    for num in string.gmatch(tostring(v1), "%d+") do table.insert(m1, tonumber(num)); end
    local m2 = {}
    for num in string.gmatch(tostring(v2), "%d+") do table.insert(m2, tonumber(num)); end

    -- If no numbers found
    if (#m1 == 0 or #m2 == 0) then return nil; end

    -- For each pair of numbers
    for i = 1, math.max(#m1, #m2) do
        if     (m1[i] or 0) < (m2[i] or 0) then return -1
        elseif (m1[i] or 0) > (m2[i] or 0) then return  1
        end
    end

    -- If all numbers were passed with no difference detected, then version are equal
    return 0
end

--- Determine if a version number is greater or equal to another one
--- @param v1 string|nil
--- @param v2 string
--- @return boolean is_greater_or_equal true if v1 is greater or equal to v2, false otherwise (including in case of error)
function m.IsVersionGreaterOrEqual(v1, v2)
	local comparison_result = m.CompareVersions(v1, v2)
	return type(comparison_result) == "number" and comparison_result >= 0
end

--- Convert and object to a hexadecimal string
--- @param data any
--- @param prefix_with_0x boolean
--- @param upper_case boolean
--- @return string hexadecimal_string
function m.ToHexString(data, prefix_with_0x, upper_case)

	-- Case when data is of type Tvb (see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
	-- or TvbRange (see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_TvbRange)
	if type(data) == "userdata" and (getmetatable(data).__name == "Tvb" or getmetatable(data).__name == "TvbRange") then
		-- Process data:bytes() as a ByteArray object
		return m.ToHexString(data:bytes(), prefix_with_0x, upper_case)
	end

	-- Case when data is of type FieldInfo (see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Field.html#lua_class_FieldInfo)
	if type(data) == "userdata" and getmetatable(data).__name == "FieldInfo" then
		-- Process data.range as a TvbRange object
		return m.ToHexString(data.range, prefix_with_0x, upper_case)
	end

	-- init result string
	local result = ""

	-- Case when data is a string
	if type(data) == "string" then
		-- Simply assign the result to that string
		result = data
	end

	-- Case when data is of type ByteArray (see: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_ByteArray)
	if type(data) == "userdata" and getmetatable(data).__name == "ByteArray" then
		-- Get hex string from data:tohex()
		result = data:tohex()
	end

	-- Force to upper case if requested
	result = upper_case and result:upper() or result:lower()

	-- prefix if required
	result = prefix_with_0x and ("0x" .. result) or result

	-- Return the resulting string
	return result

end

--- Get the size of a table
--- @param table table
--- @return number size
function m.GetTableSize(table)
	-- Init size
	local size = 0
	-- Loop through table items
	if type(table)=="table" then
		for _ in pairs(table) do
			size = size + 1
		end
	end
	-- Eventually return table size
	return size
end

--- Sort a table of tables
--- @param t table Table to sort (keys must be numbers)
--- @param key_name string|nil Name of the property where to copy the original table keys inside the item properties
--- @return table result Sorted table
function m.SortTableOfTables(t, key_name)
    local remove_key = (key_name == nil)
    key_name = key_name or "__key"
    local result = {}
    for k,v in pairs(t) do
    local item = {}
    item[key_name] = k
    for k1,v1 in pairs(v) do
        item[k1]=v1
    end
    table.insert(result, item)
    end
    table.sort(result, function(a,b) return a[key_name] < b[key_name] end)
    if remove_key then
    for k,v in pairs(result) do
        result[k][key_name] = nil
    end
    end
    return result
end

--- Print a table to console output
--- @param t table
function m.PrintTable(t)
	if type(t)=="table" then
		for k1,v1 in pairs(t) do
			print(k1,v1)
			if type(v1)=="table" then
				for k2,v2 in pairs(v1) do
					print("", k2,v2)
					if type(v2)=="table" then
						for k3,v3 in pairs(v2) do
							print("", "", k3,v3)
							if type(v3)=="table" then
								for k4,v4 in pairs(v3) do
									print("", "", "", k4,v4)
									if type(v4)=="table" then
										for k5,v5 in pairs(v4) do
											print("", "", "", k5,v5)
										end
									end
								end
							end
						end
					end
				end
			end
		end
	end
end

-- Return the module object
return m
