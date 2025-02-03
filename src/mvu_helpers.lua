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

-- Return the module object
return m
