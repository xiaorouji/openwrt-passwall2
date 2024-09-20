local api = require "luci.passwall2.api"
local appname = api.appname
local uci = api.uci
local sys = api.sys

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

m = Map(appname)
api.set_apply_on_parse(m)

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local dynamicList_write = function(self, section, value)
	local t = {}
	local t2 = {}
	if type(value) == "table" then
		local x
		for _, x in ipairs(value) do
			if x and #x > 0 then
				if not t2[x] then
					t2[x] = x
					t[#t+1] = x
				end
			end
		end
	else
		t = { value }
	end
	t = table.concat(t, " ")
	return DynamicList.write(self, section, t)
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
-- [[ ACLs Settings ]]--
s = m:section(NamedSection, arg[1], translate("ACLs"), translate("ACLs"))
s.addremove = false
s.dynamic = false

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.default = arg[1]
o.rmempty = true

use_if = s:option(Flag, "use_interface", translate("Use Interface With ACLs"))
use_if.default = 0
use_if.rmempty = false


local mac_t = {}
sys.net.mac_hints(function(e, t)
	mac_t[#mac_t + 1] = {
		ip = t,
		mac = e
	}
end)
table.sort(mac_t, function(a,b)
	if #a.ip < #b.ip then
		return true
	elseif #a.ip == #b.ip then
		if a.ip < b.ip then
			return true
		else
			return #a.ip < #b.ip
		end
	end
	return false
end)

local device_list = {}
device_list = sys.net.devices()
table.sort(device_list)
interface = s:option(ListValue, "interface", translate("Source Interface"))

for k, name in ipairs(device_list) do
	interface:value(name)
end

interface:depends({ use_interface = 1 })

---- Source
sources = s:option(DynamicList, "sources", translate("Source"))
sources.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("MAC") .. ": 00:00:00:FF:FF:FF"
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li><li>" .. translate("IP range") .. ": 192.168.1.100-192.168.1.200"
.. "</li><li>" .. translate("IPSet") .. ": ipset:lanlist"
.. "</li></ul>"
sources.cast = "string"
for _, key in pairs(mac_t) do
	sources:value(key.mac, "%s (%s)" % {key.mac, key.ip})
end
sources:depends({ use_interface = 0 })

sources.cfgvalue = function(self, section)
	local value
	if self.tag_error[section] then
		value = self:formvalue(section)
	else
		value = self.map:get(section, self.option)
		if type(value) == "string" then
			local value2 = {}
			string.gsub(value, '[^' .. " " .. ']+', function(w) table.insert(value2, w) end)
			value = value2
		end
	end
	return value
end
sources.validate = function(self, value, t)
	local err = {}
	for _, v in ipairs(value) do
		local flag = false
		if v:find("ipset:") and v:find("ipset:") == 1 then
			local ipset = v:gsub("ipset:", "")
			if ipset and ipset ~= "" then
				flag = true
			end
		end

		if flag == false and datatypes.macaddr(v) then
			flag = true
		end

		if flag == false and datatypes.ip4addr(v) then
			flag = true
		end

		if flag == false and api.iprange(v) then
			flag = true
		end

		if flag == false then
			err[#err + 1] = v
		end
	end

	if #err > 0 then
		self:add_error(t, "invalid", translate("Not true format, please re-enter!"))
		for _, v in ipairs(err) do
			self:add_error(t, "invalid", v)
		end
	end

	return value
end
sources.write = dynamicList_write

---- TCP No Redir Ports
local TCP_NO_REDIR_PORTS = uci:get(appname, "@global_forwarding[0]", "tcp_no_redir_ports")
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Use global config") .. "(" .. TCP_NO_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o.validate = port_validate

---- UDP No Redir Ports
local UDP_NO_REDIR_PORTS = uci:get(appname, "@global_forwarding[0]", "udp_no_redir_ports")
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"),
	"<font color='red'>" ..
	translate("If you don't want to let the device in the list to go proxy, please choose all.") ..
	"</font>")
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Use global config") .. "(" .. UDP_NO_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o.validate = port_validate

node = s:option(ListValue, "node", "<a style='color: red'>" .. translate("Node") .. "</a>")
node.default = "default"
node:value("default", translate("Use global config"))
for k, v in pairs(nodes_table) do
	node:value(v.id, v["remark"])
end

---- TCP Redir Ports
local TCP_REDIR_PORTS = uci:get(appname, "@global_forwarding[0]", "tcp_redir_ports")
o = s:option(Value, "tcp_redir_ports", translate("TCP Redir Ports"))
o.default = "default"
o:value("default", translate("Use global config") .. "(" .. TCP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("22,25,53,143,465,587,853,993,995,80,443", translate("Common Use"))
o:value("80,443", "80,443")
o.validate = port_validate

---- UDP Redir Ports
local UDP_REDIR_PORTS = uci:get(appname, "@global_forwarding[0]", "udp_redir_ports")
o = s:option(Value, "udp_redir_ports", translate("UDP Redir Ports"))
o.default = "default"
o:value("default", translate("Use global config") .. "(" .. UDP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o.validate = port_validate

o = s:option(ListValue, "direct_dns_query_strategy", translate("Direct Query Strategy"))
o.default = "UseIP"
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")
o:depends({ node = "default",  ['!reverse'] = true })

o = s:option(Flag, "write_ipset_direct", translate("Direct DNS result write to IPSet"), translate("Perform the matching direct domain name rules into IP to IPSet/NFTSet, and then connect directly (not entering the core). Maybe conflict with some special circumstances."))
o.default = "1"
o:depends({ node = "default",  ['!reverse'] = true })

o = s:option(ListValue, "remote_dns_protocol", translate("Remote DNS Protocol"))
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:value("udp", "UDP")
o:depends({ node = "default",  ['!reverse'] = true })

---- DNS Forward
o = s:option(Value, "remote_dns", translate("Remote DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("149.112.112.112", "149.112.112.112 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "udp")

---- DoH
o = s:option(Value, "remote_dns_doh", translate("Remote DNS DoH"))
o:value("https://1.1.1.1/dns-query", "CloudFlare")
o:value("https://1.1.1.2/dns-query", "CloudFlare-Security")
o:value("https://8.8.4.4/dns-query", "Google 8844")
o:value("https://8.8.8.8/dns-query", "Google 8888")
o:value("https://9.9.9.9/dns-query", "Quad9-Recommended 9.9.9.9")
o:value("https://149.112.112.112/dns-query", "Quad9-Recommended 149.112.112.112")
o:value("https://208.67.222.222/dns-query", "OpenDNS")
o:value("https://dns.adguard.com/dns-query,176.103.130.130", "AdGuard")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "LibreDNS")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "LibreDNS (No Ads)")
o.default = "https://1.1.1.1/dns-query"
o.validate = doh_validate
o:depends("remote_dns_protocol", "doh")

o = s:option(Value, "remote_dns_client_ip", translate("Remote DNS EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
				translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends({ __hide = true })

o = s:option(ListValue, "remote_dns_detour", translate("Remote DNS Outbound"))
o.default = "remote"
o:value("remote", translate("Remote"))
o:value("direct", translate("Direct"))
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "doh")
o:depends("remote_dns_protocol", "udp")

o = s:option(Flag, "remote_fakedns", "FakeDNS", translate("Use FakeDNS work in the shunt domain that proxy."))
o.default = "0"
o.rmempty = false
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "doh")
o:depends("remote_dns_protocol", "udp")

o = s:option(ListValue, "remote_dns_query_strategy", translate("Remote Query Strategy"))
o.default = "UseIPv4"
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "doh")
o:depends("remote_dns_protocol", "udp")

o = s:option(TextValue, "dns_hosts", translate("Domain Override"))
o.rows = 5
o.wrap = "off"
o:depends({ __hide = true })
o.remove = function(self, section)
	local node_value = node:formvalue(arg[1])
	if node_value ~= "nil" then
		local node_t = m:get(node_value) or {}
		if node_t.type == "Xray" then
			AbstractValue.remove(self, section)
		end
	end
end

for k, v in pairs(nodes_table) do
	if v.type == "Xray" then
		s.fields["remote_dns_client_ip"]:depends({ node = v.id, remote_dns_protocol = "tcp" })
		s.fields["remote_dns_client_ip"]:depends({ node = v.id, remote_dns_protocol = "doh" })
		s.fields["dns_hosts"]:depends({ node = v.id })
	end
end

return m
