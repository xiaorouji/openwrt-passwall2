local api = require "luci.passwall2.api"
local appname = api.appname

m = Map(appname)
api.set_apply_on_parse(m)

-- [[ Rule Settings ]]--
s = m:section(TypedSection, "global_rules", translate("Rule status"))
s.anonymous = true

o = s:option(Value, "v2ray_location_asset", translate("Location of V2ray/Xray asset"), translate("This variable specifies a directory where geoip.dat and geosite.dat files are."))
o.default = "/usr/share/v2ray/"
o.rmempty = false

---- Custom geo file url
o = s:option(Value, "geoip_url", translate("Custom geoip URL"))
o.default = "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"
o.rmempty = false

o = s:option(Value, "geosite_url", translate("Custom geosite URL"))
o.default = "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"
o.rmempty = false
----

if api.is_finded("geoview") then
	o = s:option(Flag, "enable_geoview", translate("Enable Geo Data Parsing"))
	o.default = 0
	o.rmempty = false
	o.description = "<ul>"
		.. "<li>" .. translate("Experimental feature.") .. "</li>"
		.. "<li>" .. translate("Analyzes and preloads GeoIP/Geosite data to enhance the shunt performance of Sing-box/Xray.") .. "</li>"
		.. "<li>" .. translate("Note: Increases resource usage.") .. "</li>"
		.. "</ul>"
end

s:append(Template(appname .. "/rule/rule_version"))

---- Auto Update
o = s:option(Flag, "auto_update", translate("Enable auto update rules"))
o.default = 0
o.rmempty = false

---- Week Update
o = s:option(ListValue, "week_update", translate("Update Mode"))
o:value(8, translate("Loop Mode"))
o:value(7, translate("Every day"))
o:value(1, translate("Every Monday"))
o:value(2, translate("Every Tuesday"))
o:value(3, translate("Every Wednesday"))
o:value(4, translate("Every Thursday"))
o:value(5, translate("Every Friday"))
o:value(6, translate("Every Saturday"))
o:value(0, translate("Every Sunday"))
o.default = 7
o:depends("auto_update", true)
o.rmempty = true

---- Time Update
o = s:option(ListValue, "time_update", translate("Update Time(every day)"))
for t = 0, 23 do o:value(t, t .. ":00") end
o.default = 0
o:depends("week_update", "0")
o:depends("week_update", "1")
o:depends("week_update", "2")
o:depends("week_update", "3")
o:depends("week_update", "4")
o:depends("week_update", "5")
o:depends("week_update", "6")
o:depends("week_update", "7")
o.rmempty = true

---- Interval Update
o = s:option(ListValue, "interval_update", translate("Update Interval(hour)"))
for t = 1, 24 do o:value(t, t .. " " .. translate("hour")) end
o.default = 2
o:depends("week_update", "8")
o.rmempty = true

s = m:section(TypedSection, "shunt_rules", "Sing-Box/Xray " .. translate("Shunt Rule"), "<a style='color: red'>" .. translate("Please note attention to the priority, the higher the order, the higher the priority.") .. "</a>")
s.template = "cbi/tblsection"
s.anonymous = false
s.addremove = true
s.sortable = true
s.extedit = api.url("shunt_rules", "%s")
function s.create(e, t)
	TypedSection.create(e, t)
	luci.http.redirect(e.extedit:format(t))
end
function s.remove(e, t)
	m.uci:foreach(appname, "nodes", function(s)
		if s["protocol"] and s["protocol"] == "_shunt" then
			m:del(s[".name"], t)
		end
	end)
	TypedSection.remove(e, t)
end

o = s:option(DummyValue, "remarks", translate("Remarks"))

return m
