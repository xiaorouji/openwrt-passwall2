local api = require "luci.passwall2.api"
local appname = api.appname
local datatypes = api.datatypes
local sys = api.sys

m = Map(appname)
api.set_apply_on_parse(m)

-- [[ Other Settings ]]--
s = m:section(TypedSection, "global_other")
s.anonymous = true

o = s:option(ListValue, "auto_detection_time", translate("Automatic detection delay"))
o:value("0", translate("Close"))
o:value("icmp", "Ping")
o:value("tcping", "TCP Ping")

o = s:option(Flag, "show_node_info", translate("Show server address and port"))
o.default = "0"

-- [[ Add the node via the link ]]--
s:append(Template(appname .. "/node_list/link_add_node"))

m:append(Template(appname .. "/node_list/node_list"))

return m
