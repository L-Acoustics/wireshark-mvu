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

-- Return the module object
return m
