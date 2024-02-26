--[[
	PrivateAuth OpenResty plugin
	Requires:
	* https://github.com/cloudflare/lua-resty-cookie
	* https://github.com/ledgetech/lua-resty-http
	* a configured DNS resolver in nginx.conf
	* a configured trusted certificate list (https://github.com/ledgetech/lua-resty-http/issues/42)
]]--

local cjson = require "cjson"
local ffi = require "ffi"

ffi.cdef[[
int CRYPTO_memcmp(const void *a, const void *b, size_t len);
]]

local ck = require "resty.cookie"
local http = require "resty.http"
local random = require "resty.random"
local str = require "resty.string"

local config = require "privateauth-access-config"

local cookieDuration = 24*60*60 -- in seconds

local shared = ngx.shared["privateauth-data"]
local slug = ngx.var["privateauth-slug"]

function crypto_random(length)
	local data = random.bytes(length, true)
	while data == nil do
		data = random.bytes(length, true)
	end
	return data
end

function random_token()
	return str.to_hex(crypto_random(32))
end

function hash_equals(a, b)
	if a == nil or b == nil then
		return false
	end

	if #a ~= #b then
		return false
	end

	if ffi.C.CRYPTO_memcmp(a, b, #a) == 0 then
		return true
	end

	return false
end

function html_escape(s)
	-- not sure why this isn't included anywhere....
	-- this does the transformations that https://www.php.net/manual/en/function.htmlspecialchars.php does
	s = s:gsub("'", "&#039;")
	s = s:gsub("\"", "&quot;")
	s = s:gsub("<", "&lt;")
	s = s:gsub(">", "&gt;")
	s = s:gsub("&", "&amp;")
	return s
end

local appInfo = config.apps[slug]

ngx.header.content_type = "text/html"

if not appInfo then
	ngx.say("Configuration error!")
	ngx.say("Could not find config for slug '" .. slug .. "'!")
	ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	return
end

local cookieName = "privateauth-orsid-" .. slug

local cookie = ck:new()

function set_session_data(sid, data)
	-- check if we have the cookie already
	local sessionCookieValue, _ = cookie:get(cookieName)
	if not sessionCookieValue then
		-- we don't, so set it
		cookie:set({
			key = cookieName,
			value = sid,
			path = "/"
		})
	end

	-- update the shared dict
	local success, err = shared:set(sid, cjson.encode(data), cookieDuration)
	if not success then
		ngx.log(ngx.ERR, err)
		return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
end

-- try to get an existing cookie
local sid, _ = cookie:get(cookieName)
local session = {
	loggedIn = false,
	state = "",
	me = ""
}
if sid then
	-- look up the session
	local result, _ = shared:get(sid)
	if result then
		-- found the session!
		session = cjson.decode(result)
	end
else
	sid = random_token()
end

local query = ngx.req.get_uri_args()

if session.loggedIn then
	if query["pa-action"] then
		return ngx.exit(ngx.HTTP_OK)
	end
	if query["pa-info"] then
		ngx.print("You are currently logged in as " .. html_escape(session.me) .. ".")
		return ngx.exit(ngx.HTTP_OK)
	end

	-- continue to the application
	return ngx.exit(ngx.OK)
else
	-- are we returning from authentication?
	if query["code"] then
		-- yes, so let's verify the code
		-- first check the state
		if not query["state"] then
			ngx.print("Missing state parameter. Authentication failed.")
			return ngx.exit(ngx.HTTP_OK)
		end
		if not hash_equals(query["state"], session["state"]) then
			ngx.print("Invalid state parameter. Authentication failed.")
			return ngx.exit(ngx.HTTP_OK)
		end

		-- then check the code
		local httpc = http.new()
		local res, err = httpc:request_uri(config.endpoint, {
			method = "POST",
			body = ngx.encode_args({
				client_id = appInfo.clientID,
				redirect_uri = appInfo.redirectURI,
				code = query["code"]
			}),
			headers = {
				["Content-Type"] = "application/x-www-form-urlencoded",
				["X-PrivateAuth-Version"] = "1"
			}
		})
		if not res then
			ngx.log(ngx.ERR, err)
			ngx.print("Could not contact PrivateAuth endpoint. Authentication failed.")
			return ngx.exit(ngx.HTTP_OK)
		end
		if res.status ~= 200 then
			ngx.log(ngx.ERR, "PrivateAuth endpoint returned status code " .. res.status .. " on verify")
			ngx.print("Invalid code parameter. Authentication failed.")
			return ngx.exit(ngx.HTTP_OK)
		end

		local endpointResponse = cjson.decode(res.body)
		if not endpointResponse["me"] or not endpointResponse["username"] then
			ngx.print("PrivateAuth endpoint returned invalid response. Authentication failed.")
			return ngx.exit(ngx.HTTP_OK)
		end

		if endpointResponse["permissions"] == nil then
			ngx.print("PrivateAuth endpoint did not return permissions array. Authentication failed.")
			return ngx.exit(ngx.HTTP_OK)
		end

		if appInfo.requirePermission ~= "" then
			local hasPermission = false
			for _, value in ipairs(endpointResponse["permissions"]) do
				if appInfo.requirePermission == value then
					hasPermission = true
					break
				end
			end

			if not hasPermission then
				ngx.print("You do not have permission to access this application.")
				return ngx.exit(ngx.HTTP_OK)
			end
		end

		session["loggedIn"] = true
		session["me"] = endpointResponse["me"]
		session["name"] = endpointResponse["name"]
		session["shortName"] = endpointResponse["shortName"]
		session["username"] = endpointResponse["username"]
		session["permissions"] = endpointResponse["permissions"]
		set_session_data(sid, session)

		-- we're done! continue to the application
		return ngx.redirect(appInfo.redirectURI)
	else
		-- no, so let's tell the user to log in
		local state = random_token()
		session["state"] = state
		set_session_data(sid, session)

		local authURL = config.endpoint .. "?" .. ngx.encode_args({
			client_id = appInfo.clientID,
			redirect_uri = appInfo.redirectURI,
			state = state
		})
		ngx.status = ngx.HTTP_FORBIDDEN
		ngx.print('<div class="h-app">')
		ngx.print('<h1 class="p-name">' .. appInfo.name .. '</h1>')
		ngx.print('<div class="p-url" style="display: none">' .. appInfo.clientID .. '</div>')
		ngx.print('Authentication is required. ')
		ngx.print('<a href="' .. authURL .. '">Log in</a>')
		ngx.print('</div>')
		return ngx.exit(ngx.status)
	end
end
