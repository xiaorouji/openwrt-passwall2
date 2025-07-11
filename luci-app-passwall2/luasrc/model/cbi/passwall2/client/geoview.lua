local api = require "luci.passwall2.api"
local appname = "passwall2"
local fs = api.fs
local uci = api.uci

local geo_dir = (uci:get(appname, "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"):match("^(.*)/")
local geosite_path = geo_dir .. "/geosite.dat"
local geoip_path = geo_dir .. "/geoip.dat"
if fs.access(geosite_path) and fs.access(geoip_path) then
    f = SimpleForm(appname)
    f.reset = false
    f.submit = false
    f:append(Template(appname .. "/rule/geoview"))
end

return f