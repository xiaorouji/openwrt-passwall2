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

local auto_detection_time = m:get("@global_other[0]", "auto_detection_time") or "0"
local show_node_info = m:get("@global_other[0]", "show_node_info") or "0"

-- [[ Node List ]]--
s = m:section(TypedSection, "nodes")
s.anonymous = true
s.extedit = api.url("node_config", "%s")
s.sortable = true
s.template = "cbi/tblsection"

o = s:option(DummyValue, "group", translate("Group Name"))
o.width = "10%"

o = s:option(DummyValue, "remarks", translate("Remarks"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local str = ""
	local is_sub = m:get(n, "is_sub") or ""
	local group = m:get(n, "group") or ""
	local remarks = m:get(n, "remarks") or ""
	local type = m:get(n, "type") or ""
	str = str .. string.format("<input type='hidden' id='cbid.%s.%s.type' value='%s'/>", appname, n, type)
	if type == "sing-box" or type == "Xray" then
		local protocol = m:get(n, "protocol")
		if protocol == "_balancing" then
			protocol = translate("Balancing")
		elseif protocol == "_urltest" then
			protocol = "URLTest"
		elseif protocol == "_shunt" then
			protocol = translate("Shunt")
		elseif protocol == "vmess" then
			protocol = "VMess"
		elseif protocol == "vless" then
			protocol = "VLESS"
		elseif protocol == "shadowsocks" then
			protocol = "SS"
		elseif protocol == "shadowsocksr" then
			protocol = "SSR"
		elseif protocol == "wireguard" then
			protocol = "WG"
		elseif protocol == "hysteria" then
			protocol = "HY"
		elseif protocol == "hysteria2" then
			protocol = "HY2"
		elseif protocol == "anytls" then
			protocol = "AnyTLS"
		elseif protocol == "ssh" then
			protocol = "SSH"
		else
			protocol = protocol:gsub("^%l",string.upper)
		end
		if type == "sing-box" then type = "Sing-Box" end
		type = type .. " " .. protocol
	end
	local address = m:get(n, "address") or ""
	local port = m:get(n, "port") or ""
	local port_s = (port ~= "") and port or m:get(n, "hysteria_hop") or m:get(n, "hysteria2_hop") or ""
	str = str .. translate(type) .. "：" .. remarks
	if address ~= "" and port_s ~= "" then
		port_s = port_s:gsub(":", "-")
		if show_node_info == "1" then
			if datatypes.ip6addr(address) then
				str = str .. string.format("（[%s]:%s）", address, port_s)
			else
				str = str .. string.format("（%s:%s）", address, port_s)
			end
		end
	end
	str = str .. string.format("<input type='hidden' id='cbid.%s.%s.address' value='%s'/>", appname, n, address)
	str = str .. string.format("<input type='hidden' id='cbid.%s.%s.port' value='%s'/>", appname, n, port)
	return str
end

o = s:option(DummyValue, "ping", "Ping")
o.width = "8%"
o.rawhtml = true
o.cfgvalue = function(t, n)
	local result = "---"
	if auto_detection_time ~= "icmp" then
		result = string.format('<span class="ping"><a href="javascript:void(0)" onclick="javascript:ping_node(\'%s\', this, \'icmp\')">%s</a></span>', n, translate("Test"))
	else
		result = string.format('<span class="ping_value" cbiid="%s">---</span>', n)
	end
	return result
end

o = s:option(DummyValue, "tcping", "TCPing")
o.width = "8%"
o.rawhtml = true
o.cfgvalue = function(t, n)
	local result = "---"
	if auto_detection_time ~= "tcping" then
		result = string.format('<span class="ping"><a href="javascript:void(0)" onclick="javascript:ping_node(\'%s\', this, \'tcping\')">%s</a></span>', n, translate("Test"))
	else
		result = string.format('<span class="tcping_value" cbiid="%s">---</span>', n)
	end
	return result
end

o = s:option(DummyValue, "_url_test", translate("URL Test"))
o.width = "8%"
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<span class="ping"><a href="javascript:void(0)" onclick="javascript:urltest_node(\'%s\', this)">%s</a></span>', n, translate("Test"))
end

m:append(Template(appname .. "/node_list/node_list"))

return m
