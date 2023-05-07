local api = require "luci.passwall2.api"
local appname = api.appname
local uci = api.uci
local datatypes = api.datatypes
local has_v2ray = api.is_finded("v2ray")
local has_xray = api.is_finded("xray")

m = Map(appname)

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local doh_validate = function(self, value, t)
	if value ~= "" then
		local flag = 0
		local util = require "luci.util"
		local val = util.split(value, ",")
		local url = val[1]
		val[1] = nil
		for i = 1, #val do
			local v = val[i]
			if v then
				if not datatypes.ipmask4(v) then
					flag = 1
				end
			end
		end
		if flag == 0 then
			return value
		end
	end
	return nil, translate("DoH request address") .. " " .. translate("Format must be:") .. " URL,IP"
end

m:append(Template(appname .. "/global/status"))

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false

local auto_switch_tip
local shunt_remark
local current_node = luci.sys.exec(string.format("[ -f '/tmp/etc/%s/id/global' ] && echo -n $(cat /tmp/etc/%s/id/global)", appname, appname))
if current_node and current_node ~= "" and current_node ~= "nil" then
	local n = uci:get_all(appname, current_node)
	if n then
		if tonumber(m:get("@auto_switch[0]", "enable") or 0) == 1 then
			if n.protocol == "_shunt" then
				local shunt_logic = tonumber(m:get("@auto_switch[0]", "shunt_logic"))
				if shunt_logic == 1 or shunt_logic == 2 then
					if shunt_logic == 1 then
						shunt_remark = "default"
					elseif shunt_logic == 2 then
						shunt_remark = "main"
					end
					current_node = luci.sys.exec(string.format("[ -f '/tmp/etc/%s/id/global_%s' ] && echo -n $(cat /tmp/etc/%s/id/global_%s)", appname, shunt_remark, appname, shunt_remark))
					if current_node and current_node ~= "" and current_node ~= "nil" then
						n = uci:get_all(appname, current_node)
					end
				end
			end
			if n then
				local remarks = api.get_node_remarks(n)
				local url = api.url("node_config", n[".name"])
				auto_switch_tip = translatef("Current node: %s", string.format('<a href="%s">%s</a>', url, remarks)) .. "<br />"
			end
		end
	end
end

---- Node
node = s:taboption("Main", ListValue, "node", "<a style='color: red'>" .. translate("Node") .. "</a>")
node:value("nil", translate("Close"))
if not shunt_remark and auto_switch_tip then
	node.description = auto_switch_tip
end

-- 分流
if (has_v2ray or has_xray) and #nodes_table > 0 then
	local normal_list = {}
	local balancing_list = {}
	local shunt_list = {}
	for k, v in pairs(nodes_table) do
		if v.node_type == "normal" then
			normal_list[#normal_list + 1] = v
		end
		if v.protocol and v.protocol == "_balancing" then
			balancing_list[#balancing_list + 1] = v
		end
		if v.protocol and v.protocol == "_shunt" then
			shunt_list[#shunt_list + 1] = v
		end
	end

	local function get_cfgvalue(shunt_node_id, option)
		return function(self, section)
			return m:get(shunt_node_id, option) or "nil"
		end
	end
	local function get_write(shunt_node_id, option)
		return function(self, section, value)
			m:set(shunt_node_id, option, value)
		end
	end
	if #normal_list > 0 then
		for k, v in pairs(shunt_list) do
			local vid = v.id
			-- shunt node type, V2ray or Xray
			local type = s:taboption("Main", ListValue, vid .. "-type", translate("Type"))
			if has_v2ray then
				type:value("V2ray", translate("V2ray"))
			end
			if has_xray then
				type:value("Xray", translate("Xray"))
			end
			type.cfgvalue = get_cfgvalue(v.id, "type")
			type.write = get_write(v.id, "type")
			
			-- pre-proxy
			o = s:taboption("Main", Flag, vid .. "-preproxy_enabled", translate("Preproxy"))
			o:depends("node", v.id)
			o.rmempty = false
			o.cfgvalue = get_cfgvalue(v.id, "preproxy_enabled")
			o.write = get_write(v.id, "preproxy_enabled")

			o = s:taboption("Main", Value, vid .. "-main_node", string.format('<a style="color:red">%s</a>', translate("Preproxy Node")), translate("Set the node to be used as a pre-proxy. Each rule (including <code>Default</code>) has a separate switch that controls whether this rule uses the pre-proxy or not."))
			o:depends(vid .. "-preproxy_enabled", "1")
			for k1, v1 in pairs(balancing_list) do
				o:value(v1.id, v1.remark)
			end
			for k1, v1 in pairs(normal_list) do
				o:value(v1.id, v1.remark)
			end
			if #o.keylist > 0 then
				o.default = o.keylist[1]
			end
			o.cfgvalue = get_cfgvalue(v.id, "main_node")
			o.write = get_write(v.id, "main_node")
			if shunt_remark == "main" and auto_switch_tip then
				o.description = auto_switch_tip
			end

			if (has_v2ray and has_xray) or (v.type == "V2ray" and not has_v2ray) or (v.type == "Xray" and not has_xray) then
				type:depends("node", v.id)
			else
				type:depends("node", "hide") --不存在的依赖，即始终隐藏
			end

			uci:foreach(appname, "shunt_rules", function(e)
				local id = e[".name"]
				local node_option = vid .. "-" .. id .. "_node"
				if id and e.remarks then
					o = s:taboption("Main", Value, node_option, string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", id), e.remarks))
					o.cfgvalue = get_cfgvalue(v.id, id)
					o.write = get_write(v.id, id)
					o:depends("node", v.id)
					o.default = "nil"
					o:value("nil", translate("Close"))
					o:value("_default", translate("Default"))
					o:value("_direct", translate("Direct Connection"))
					o:value("_blackhole", translate("Blackhole"))

					local pt = s:taboption("Main", ListValue, vid .. "-".. id .. "_proxy_tag", string.format('* <a style="color:red">%s</a>', e.remarks .. " " .. translate("Preproxy")))
					pt.cfgvalue = get_cfgvalue(v.id, id .. "_proxy_tag")
					pt.write = get_write(v.id, id .. "_proxy_tag")
					pt:value("nil", translate("Close"))
					pt:value("main", translate("Preproxy Node"))
					pt.default = "nil"
					for k1, v1 in pairs(balancing_list) do
						o:value(v1.id, v1.remark)
					end
					for k1, v1 in pairs(normal_list) do
						o:value(v1.id, v1.remark)
						pt:depends({ [node_option] = v1.id, [vid .. "-preproxy_enabled"] = "1" })
					end
				end
			end)

			local id = "default_node"
			o = s:taboption("Main", Value, vid .. "-" .. id, string.format('* <a style="color:red">%s</a>', translate("Default")))
			o.cfgvalue = get_cfgvalue(v.id, id)
			o.write = get_write(v.id, id)
			o:depends("node", v.id)
			o.default = "_direct"
			o:value("_direct", translate("Direct Connection"))
			o:value("_blackhole", translate("Blackhole"))
			for k1, v1 in pairs(balancing_list) do
				o:value(v1.id, v1.remark)
			end
			for k1, v1 in pairs(normal_list) do
				o:value(v1.id, v1.remark)
			end
			if shunt_remark == "default" and auto_switch_tip then
				o.description = auto_switch_tip
			end

			local id = "default_proxy_tag"
			o = s:taboption("Main", ListValue, vid .. "-" .. id, string.format('* <a style="color:red">%s</a>', translate("Default Preproxy")), translate("When using, localhost will connect this node first and then use this node to connect the default node."))
			o.cfgvalue = get_cfgvalue(v.id, id)
			o.write = get_write(v.id, id)
			o:value("nil", translate("Close"))
			o:value("main", translate("Preproxy Node"))
			for k1, v1 in pairs(normal_list) do
				if v1.protocol ~= "_balancing" then
					o:depends({ [vid .. "-default_node"] = v1.id, [vid .. "-preproxy_enabled"] = "1" })
				end
			end
		end
	else
		local tips = s:taboption("Main", DummyValue, "tips", " ")
		tips.rawhtml = true
		tips.cfgvalue = function(t, n)
			return string.format('<a style="color: red">%s</a>', translate("There are no available nodes, please add or subscribe nodes first."))
		end
		tips:depends({ node = "nil", ["!reverse"] = true })
		for k, v in pairs(shunt_list) do
			tips:depends("node", v.id)
		end
		for k, v in pairs(balancing_list) do
			tips:depends("node", v.id)
		end
	end
end

o = s:taboption("Main", Flag, "localhost_proxy", translate("Localhost Proxy"), translate("When selected, localhost can transparent proxy."))
o.default = "1"
o.rmempty = false

node_socks_port = s:taboption("Main", Value, "node_socks_port", translate("Node") .. " Socks " .. translate("Listen Port"))
node_socks_port.default = 1070
node_socks_port.datatype = "port"

--[[
if has_v2ray or has_xray then
	node_http_port = s:taboption("Main", Value, "node_http_port", translate("Node") .. " HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	node_http_port.default = 0
	node_http_port.datatype = "port"
end
]]--

s:tab("DNS", translate("DNS"))

o = s:taboption("DNS", ListValue, "direct_dns_protocol", translate("Direct DNS Protocol"))
o.default = "auto"
o:value("auto", translate("Auto"))
o:value("udp", "UDP")
o:value("tcp", "TCP")
o:value("doh", "DoH")

---- DNS Forward
o = s:taboption("DNS", Value, "direct_dns", translate("Direct DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "119.29.29.29"
o:value("114.114.114.114", "114.114.114.114 (114DNS)")
o:value("119.29.29.29", "119.29.29.29 (DNSPod)")
o:value("223.5.5.5", "223.5.5.5 (AliDNS)")
o:depends("direct_dns_protocol", "udp")
o:depends("direct_dns_protocol", "tcp")

---- DoH
o = s:taboption("DNS", Value, "direct_dns_doh", translate("Direct DNS DoH"))
o.default = "https://223.5.5.5/dns-query"
o:value("https://1.12.12.12/dns-query", "DNSPod 1")
o:value("https://120.53.53.53/dns-query", "DNSPod 2")
o:value("https://223.5.5.5/dns-query", "AliDNS")
o.validate = doh_validate
o:depends("direct_dns_protocol", "doh")

o = s:taboption("DNS", Value, "direct_dns_client_ip", translate("Direct DNS EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
				translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends("direct_dns_protocol", "tcp")
o:depends("direct_dns_protocol", "doh")

o = s:taboption("DNS", ListValue, "direct_dns_query_strategy", translate("Direct Query Strategy"))
o.default = "UseIP"
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")

o = s:taboption("DNS", ListValue, "remote_dns_protocol", translate("Remote DNS Protocol"))
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:value("udp", "UDP")

---- DNS Forward
o = s:taboption("DNS", Value, "remote_dns", translate("Remote DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "udp")

---- DoH
o = s:taboption("DNS", Value, "remote_dns_doh", translate("Remote DNS DoH"))
o.default = "https://1.1.1.1/dns-query"
o:value("https://1.1.1.1/dns-query", "CloudFlare")
o:value("https://1.1.1.2/dns-query", "CloudFlare-Security")
o:value("https://8.8.4.4/dns-query", "Google 8844")
o:value("https://8.8.8.8/dns-query", "Google 8888")
o:value("https://9.9.9.9/dns-query", "Quad9-Recommended")
o:value("https://208.67.222.222/dns-query", "OpenDNS")
o:value("https://dns.adguard.com/dns-query,176.103.130.130", "AdGuard")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "LibreDNS")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "LibreDNS (No Ads)")
o.validate = doh_validate
o:depends("remote_dns_protocol", "doh")

o = s:taboption("DNS", Value, "remote_dns_client_ip", translate("Remote DNS EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
				translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "doh")

o = s:taboption("DNS", Flag, "remote_fakedns", "FakeDNS", translate("Use FakeDNS work in the shunt domain that proxy."))
o.default = "0"
o.rmempty = false

o = s:taboption("DNS", ListValue, "remote_dns_query_strategy", translate("Remote Query Strategy"))
o.default = "UseIPv4"
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")

hosts = s:taboption("DNS", TextValue, "dns_hosts", translate("Domain Override"))
hosts.rows = 5
hosts.wrap = "off"

o = s:taboption("DNS", Button, "clear_ipset", translate("Clear IPSET"), translate("Try this feature if the rule modification does not take effect."))
o.inputstyle = "remove"
function o.write(e, e)
	luci.sys.call("[ -n \"$(nft list sets 2>/dev/null | grep \"passwall2_\")\" ] && sh /usr/share/" .. appname .. "/nftables.sh flush_nftset || sh /usr/share/" .. appname .. "/iptables.sh flush_ipset > /dev/null 2>&1 &")
	luci.http.redirect(api.url("log"))
end

s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "close_log", translate("Close Node Log"))
o.rmempty = false

loglevel = s:taboption("log", ListValue, "loglevel", translate("Log Level"))
loglevel.default = "warning"
loglevel:value("debug")
loglevel:value("info")
loglevel:value("warning")
loglevel:value("error")

s:tab("faq", "FAQ")

o = s:taboption("faq", DummyValue, "")
o.template = appname .. "/global/faq"

-- [[ Socks Server ]]--
o = s:taboption("Main", Flag, "socks_enabled", "Socks " .. translate("Main switch"))
o.rmempty = false

s = m:section(TypedSection, "socks", translate("Socks Config"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"
function s.create(e, t)
	TypedSection.create(e, api.gen_short_uuid())
end

o = s:option(DummyValue, "status", translate("Status"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<div class="_status" socks_id="%s"></div>', n)
end

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

socks_node = s:option(ListValue, "node", translate("Socks Node"))

local n = 1
uci:foreach(appname, "socks", function(s)
	if s[".name"] == section then
		return false
	end
	n = n + 1
end)

o = s:option(Value, "port", "Socks " .. translate("Listen Port"))
o.default = n + 1080
o.datatype = "port"
o.rmempty = false

if has_v2ray or has_xray then
	o = s:option(Value, "http_port", "HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	o.default = 0
	o.datatype = "port"
end

for k, v in pairs(nodes_table) do
	node:value(v.id, v["remark"])
	if v.type == "Socks" then
		if has_v2ray or has_xray then
			socks_node:value(v.id, v["remark"])
		end
	else
		socks_node:value(v.id, v["remark"])
	end
end

m:append(Template(appname .. "/global/footer"))

return m
