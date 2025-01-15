---
--- helpers.lua
---
--- Global helper functions
---

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

-- Return the module object
return m
