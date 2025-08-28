#!/usr/bin/lua

local api = require "luci.passwall2.api"
local name = api.appname
local fs = api.fs
local sys = api.sys
local uci = api.uci
local jsonc = api.jsonc

local arg1 = arg[1]
local arg2 = arg[2]
local arg3 = arg[3]

local reboot = 0
local geoip_update = 0
local geosite_update = 0
local asset_location = uci:get_first(name, 'global_rules', "v2ray_location_asset", "/usr/share/v2ray/")

-- Custom geo file
local geoip_api = uci:get_first(name, 'global_rules', "geoip_url", "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest")
local geosite_api = uci:get_first(name, 'global_rules', "geosite_url", "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest")
--
local use_nft = uci:get(name, "@global_forwarding[0]", "use_nft") or "0"

if arg3 == "cron" then
	arg2 = nil
end

local log = function(...)
	if arg1 then
		if arg1 == "log" then
			api.log(...)
		elseif arg1 == "print" then
			local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
			print(result)
		end
	end
end

-- curl
local function curl(url, file)
	local args = {
		"-skL", "-w %{http_code}", "--retry 3", "--connect-timeout 3", "--max-time 300", "--speed-limit 51200 --speed-time 15"
	}
	if file then
		args[#args + 1] = "-o " .. file
	end
	local return_code, result = api.curl_logic(url, nil, args)
	return tonumber(result)
end

--获取geoip
local function fetch_geoip()
	--请求geoip
	xpcall(function()
		local return_code, content = api.curl_logic(geoip_api)
		local json = jsonc.parse(content)
		if json.tag_name and json.assets then
			for _, v in ipairs(json.assets) do
				if v.name and v.name == "geoip.dat.sha256sum" then
					local sret = curl(v.browser_download_url, "/tmp/geoip.dat.sha256sum")
					if sret == 200 then
						local f = io.open("/tmp/geoip.dat.sha256sum", "r")
						local content = f:read()
						f:close()
						f = io.open("/tmp/geoip.dat.sha256sum", "w")
						f:write(content:gsub("geoip.dat", "/tmp/geoip.dat"), "")
						f:close()

						if fs.access(asset_location .. "geoip.dat") then
							sys.call(string.format("cp -f %s %s", asset_location .. "geoip.dat", "/tmp/geoip.dat"))
							if sys.call('sha256sum -c /tmp/geoip.dat.sha256sum > /dev/null 2>&1') == 0 then
								log("geoip 版本一致，无需更新。")
								return 1
							end
						end
						for _2, v2 in ipairs(json.assets) do
							if v2.name and v2.name == "geoip.dat" then
								sret = curl(v2.browser_download_url, "/tmp/geoip.dat")
								if sys.call('sha256sum -c /tmp/geoip.dat.sha256sum > /dev/null 2>&1') == 0 then
									sys.call(string.format("mkdir -p %s && cp -f %s %s", asset_location, "/tmp/geoip.dat", asset_location .. "geoip.dat"))
									reboot = 1
									log("geoip 更新成功。")
									return 1
								else
									log("geoip 更新失败，请稍后再试。")
								end
								break
							end
						end
					end
					break
				end
			end
		end
		if json.message then
			log(json.message)
		end
	end,
	function(e)
	end)

	return 0
end

--获取geosite
local function fetch_geosite()
	--请求geosite
	xpcall(function()
		local return_code, content = api.curl_logic(geosite_api)
		local json = jsonc.parse(content)
		if json.tag_name and json.assets then
			for _, v in ipairs(json.assets) do
				if v.name and (v.name == "geosite.dat.sha256sum" or v.name == "dlc.dat.sha256sum") then
					local sret = curl(v.browser_download_url, "/tmp/geosite.dat.sha256sum")
					if sret == 200 then
						local f = io.open("/tmp/geosite.dat.sha256sum", "r")
						local content = f:read()
						f:close()
						f = io.open("/tmp/geosite.dat.sha256sum", "w")
						f:write(content:gsub("[^%s]+.dat", "/tmp/geosite.dat"), "")
						f:close()

						if fs.access(asset_location .. "geosite.dat") then
							sys.call(string.format("cp -f %s %s", asset_location .. "geosite.dat", "/tmp/geosite.dat"))
							if sys.call('sha256sum -c /tmp/geosite.dat.sha256sum > /dev/null 2>&1') == 0 then
								log("geosite 版本一致，无需更新。")
								return 1
							end
						end
						for _2, v2 in ipairs(json.assets) do
							if v2.name and (v2.name == "geosite.dat" or v2.name == "dlc.dat") then
								sret = curl(v2.browser_download_url, "/tmp/geosite.dat")
								if sys.call('sha256sum -c /tmp/geosite.dat.sha256sum > /dev/null 2>&1') == 0 then
									sys.call(string.format("mkdir -p %s && cp -f %s %s", asset_location, "/tmp/geosite.dat", asset_location .. "geosite.dat"))
									reboot = 1
									log("geosite 更新成功。")
									return 1
								else
									log("geosite 更新失败，请稍后再试。")
								end
								break
							end
						end
					end
					break
				end
			end
		end
		if json.message then
			log(json.message)
		end
	end,
	function(e)
	end)

	return 0
end

if arg2 then
	string.gsub(arg2, '[^' .. "," .. ']+', function(w)
		if w == "geoip" then
			geoip_update = 1
		end
		if w == "geosite" then
			geosite_update = 1
		end
	end)
else
	geoip_update = uci:get_first(name, 'global_rules', "geoip_update", 1)
	geosite_update = uci:get_first(name, 'global_rules', "geosite_update", 1)
end
if geoip_update == 0 and geosite_update == 0 then
	os.exit(0)
end

log("开始更新规则...")

if tonumber(geoip_update) == 1 then
	log("geoip 开始更新...")
	local status = fetch_geoip()
	os.remove("/tmp/geoip.dat")
	os.remove("/tmp/geoip.dat.sha256sum")
end

if tonumber(geosite_update) == 1 then
	log("geosite 开始更新...")
	local status = fetch_geosite()
	os.remove("/tmp/geosite.dat")
	os.remove("/tmp/geosite.dat.sha256sum")
end

uci:set(name, uci:get_first(name, 'global_rules'), "geoip_update", geoip_update)
uci:set(name, uci:get_first(name, 'global_rules'), "geosite_update", geosite_update)
api.uci_save(uci, name, true)

if reboot == 1 then
	if arg3 == "cron" then
		if not fs.access("/var/lock/" .. name .. ".lock") then
			sys.call("touch /tmp/lock/" .. name .. "_cron.lock")
		end
	end

	log("重启服务，应用新的规则。")
	uci:set(name, "@global[0]", "flush_set", "1")
	api.uci_save(uci, name, true, true)
end
log("规则更新完毕...")
