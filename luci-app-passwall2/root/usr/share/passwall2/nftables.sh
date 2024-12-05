#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/nftables.sh
NFTABLE_NAME="inet passwall2"
NFTSET_LANLIST="passwall2_lanlist"
NFTSET_VPSLIST="passwall2_vpslist"

NFTSET_LANLIST6="passwall2_lanlist6"
NFTSET_VPSLIST6="passwall2_vpslist6"

FORCE_INDEX=0

. /lib/functions/network.sh

FWI=$(uci -q get firewall.passwall2.path 2>/dev/null)
FAKE_IP="198.18.0.0/16"
FAKE_IP_6="fc00::/18"

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	# acl mac address
	elif [ -n "$(echo $1 | grep -E '([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}')" ]; then
		echo "$2 {$1}"
	else
		echo "$2 {$(echo $1 | sed 's/:/-/g')}"
	fi
}

insert_rule_before() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

insert_rule_after() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		echolog "索引列举方式不正确（nftables），终止执行！"
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="counter redirect"
	[ -n "$1" ] && {
		local s="$s to :$1"
		[ "$2" == "MARK" ] && s="counter meta mark set $1"
		[ "$2" == "TPROXY" ] && {
			s="counter meta mark 1 tproxy to :$1"
		}
		[ "$2" == "TPROXY4" ] && {
			s="counter meta mark 1 tproxy ip to :$1"
		}
		[ "$2" == "TPROXY6" ] && {
			s="counter meta mark 1 tproxy ip6 to :$1"
		}

	}
	echo $s
}

destroy_nftset() {
	for i in "$@"; do
		nft flush set $NFTABLE_NAME $i 2>/dev/null
		nft delete set $NFTABLE_NAME $i 2>/dev/null
	done
}

gen_nft_tables() {
	if [ -z "$(nft list tables | grep 'inet passwall2')" ]; then
		local nft_table_file="$TMP_PATH/PSW2_TABLE.nft"
		# Set the correct priority to fit fw4
		cat > "$nft_table_file" <<-EOF
		table $NFTABLE_NAME {
			chain dstnat {
				type nat hook prerouting priority dstnat - 1; policy accept;
			}
			chain mangle_prerouting {
				type filter hook prerouting priority mangle - 1; policy accept;
			}
			chain mangle_output {
				type route hook output priority mangle - 1; policy accept;
			}
			chain nat_output {
				type nat hook output priority -1; policy accept;
			}
		}
		EOF

		nft -f "$nft_table_file"
		rm -rf "$nft_table_file"
	fi
}

insert_nftset() {
	local nftset_name="${1}"; shift
	local timeout_argument="${1}"; shift
	local defalut_timeout_argument="3650d"
	local nftset_elements

	[ -n "${1}" ] && {
		if [ "$timeout_argument" == "-1" ]; then
			nftset_elements=$(echo -e $@ | sed 's/\s/, /g')
		elif [ "$timeout_argument" == "0" ]; then
			nftset_elements=$(echo -e $@ | sed "s/\s/ timeout $defalut_timeout_argument, /g" | sed "s/$/ timeout $defalut_timeout_argument/")
		else
			nftset_elements=$(echo -e $@ | sed "s/\s/ timeout $timeout_argument, /g" | sed "s/$/ timeout $timeout_argument/")
		fi
		mkdir -p $TMP_PATH2/nftset
		cat > "$TMP_PATH2/nftset/$nftset_name" <<-EOF
			define $nftset_name = {$nftset_elements}	
			add element $NFTABLE_NAME $nftset_name \$$nftset_name
		EOF
		nft -f "$TMP_PATH2/nftset/$nftset_name"
		rm -rf "$TMP_PATH2/nftset"
	}
}

gen_nftset() {
	local nftset_name="${1}"; shift
	local ip_type="${1}"; shift
	#  0 - don't set defalut timeout
	local timeout_argument_set="${1}"; shift
	#  0 - don't let element timeout(3650 days) when set's timeout parameters be seted
	# -1 - follow the set's timeout parameters
	local timeout_argument_element="${1}"; shift

	nft "list set $NFTABLE_NAME $nftset_name" &>/dev/null
	if [ $? -ne 0 ]; then
		if [ "$timeout_argument_set" == "0" ]; then
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; auto-merge; }"
		else
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; timeout $timeout_argument_set; gc-interval $timeout_argument_set; auto-merge; }"
		fi
	fi
	[ -n "${1}" ] && insert_nftset $nftset_name $timeout_argument_element $@
}

get_action_chain_name() {
	echo "全局代理"
}

gen_lanlist() {
	cat <<-EOF
		0.0.0.0/8
		10.0.0.0/8
		100.64.0.0/10
		127.0.0.0/8
		169.254.0.0/16
		172.16.0.0/12
		192.168.0.0/16
		224.0.0.0/4
		240.0.0.0/4
	EOF
}

gen_lanlist_6() {
	cat <<-EOF
		::/128
		::1/128
		::ffff:0:0/96
		::ffff:0:0:0/96
		64:ff9b::/96
		100::/64
		2001::/32
		2001:20::/28
		2001:db8::/32
		2002::/16
		fc00::/7
		fe80::/10
		ff00::/8
	EOF
}

get_wan_ip() {
	local NET_IF
	local NET_ADDR
	
	network_flush_cache
	network_find_wan NET_IF
	network_get_ipaddr NET_ADDR "${NET_IF}"
	
	echo $NET_ADDR
}

get_wan6_ip() {
	local NET_IF
	local NET_ADDR
	
	network_flush_cache
	network_find_wan6 NET_IF
	network_get_ipaddr6 NET_ADDR "${NET_IF}"
	
	echo $NET_ADDR
}

load_acl() {
	[ "$ENABLED_ACLS" == 1 ] && {
		acl_app
		echolog "访问控制："
		for sid in $(ls -F ${TMP_ACL_PATH} | grep '/$' | awk -F '/' '{print $1}' | grep -v 'default'); do
			eval $(uci -q show "${CONFIG}.${sid}" | cut -d'.' -sf 3-)

			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			tcp_proxy_mode="global"
			udp_proxy_mode="global"
			node=${node:-default}
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			[ "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
			[ "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS

			node_remark=$(config_n_get $NODE remarks)
			[ -s "${TMP_ACL_PATH}/${sid}/var_node" ] && node=$(cat ${TMP_ACL_PATH}/${sid}/var_node)
			[ -s "${TMP_ACL_PATH}/${sid}/var_port" ] && redir_port=$(cat ${TMP_ACL_PATH}/${sid}/var_port)
			[ -n "$node" ] && [ "$node" != "default" ] && node_remark=$(config_n_get $node remarks)

			write_ipset_direct=${write_ipset_direct:-1}
			[ "${write_ipset_direct}" = "1" ] && {
				if [ "$node" = "default" ]; then
					local nftset_whitelist=${nftset_global_whitelist}
					local nftset_whitelist6=${nftset_global_whitelist6}
				else
					local nftset_whitelist="passwall2_${sid}_whitelist"
					local nftset_whitelist6="passwall2_${sid}_whitelist6"
					gen_nftset $nftset_whitelist ipv4_addr 3d 3d
					gen_nftset $nftset_whitelist6 ipv6_addr 3d 3d

					#分流规则的IP列表(使用分流节点时导入)
					local _USE_SHUNT_NODE=0
					_NODE_PROTOCOL=$(config_n_get $node protocol)
					[ "$_NODE_PROTOCOL" = "_shunt" ] && _USE_SHUNT_NODE=1
					[ "$_USE_SHUNT_NODE" = "1" ] && {
						local _SHUNT_DEFAULT_NODE=$(config_n_get $NODE default_node _direct)
						local _GEOIP_CODE=""
						local _shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
						for _shunt_id in $_shunt_ids; do
							local _SHUNT_RULE_NODE=$(config_n_get $NODE ${_shunt_id} nil)
							[ "${_SHUNT_RULE_NODE}" == "_default" ] && _SHUNT_RULE_NODE=${_SHUNT_DEFAULT_NODE}
							[ "${_SHUNT_RULE_NODE}" == "_direct" ] && {
								insert_nftset $ipset_whitelist "0" $(config_n_get $_shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
								insert_nftset $ipset_whitelist6 "0" $(config_n_get $_shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
								[ "$(config_t_get global_rules enable_geoview)" = "1" ] && {
									local _geoip_code=$(config_n_get $_shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
									[ -n "$_geoip_code" ] && _GEOIP_CODE="${_GEOIP_CODE:+$_GEOIP_CODE,}$_geoip_code"
								}
							}
						done
					}

					if [ -n "$_GEOIP_CODE" ] && type geoview &> /dev/null; then
						insert_nftset $ipset_whitelist "0" $(get_geoip $_GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
						insert_nftset $ipset_whitelist6 "0" $(get_geoip $_GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
						echolog "  - [$?]解析并加入分流节点 GeoIP 到 IPSET 完成"
					fi
				fi
			}

			_acl_list=${TMP_ACL_PATH}/${sid}/source_list

			for i in $(cat $_acl_list); do
				local _ipt_source
				local msg
				if [ -n "${interface}" ]; then
					. /lib/functions/network.sh
					local gateway device
					network_get_gateway gateway "${interface}"
					network_get_device device "${interface}"
					[ -z "${device}" ] && device="${interface}"
					_ipt_source="iifname ${device} "
					msg="源接口【${device}】，"
				fi
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "${_ipt_source}ip saddr")
					msg="${msg}IP range【${_iprange}】，"
					unset _iprange
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					_ipt_source="${_ipt_source}ip daddr @${_ipset}"
					msg="${msg}NFTset【${_ipset}】，"
					unset _ipset
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "${_ipt_source}ip saddr")
					msg="${msg}IP【${_ip}】，"
					unset _ip
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "${_ipt_source}ether saddr")
					msg="${msg}MAC【${_mac}】，"
					unset _mac
				else
					continue
				fi
				msg="【$remarks】，${msg}"
				
				[ "$tcp_no_redir_ports" != "disable" ] && {
					if [ "$tcp_no_redir_ports" != "1:65535" ]; then
						nft "add rule $NFTABLE_NAME $nft_prerouting_chain ${_ipt_source} ip protocol tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ${_ipt_source} meta l4proto tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
						echolog "  - ${msg}不代理 TCP 端口[${tcp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						tcp_proxy_mode="disable"
						echolog "  - ${msg}不代理所有 TCP"
					fi
				}
				
				[ "$udp_no_redir_ports" != "disable" ] && {
					if [ "$udp_no_redir_ports" != "1:65535" ]; then
						nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\"" 2>/dev/null
						echolog "  - ${msg}不代理 UDP 端口[${udp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						udp_proxy_mode="disable"
						echolog "  - ${msg}不代理所有 UDP"
					fi
				}

				[ "$tcp_proxy_mode" != "disable" ] && [ -n "$redir_port" ] && {
					[ -s "${TMP_ACL_PATH}/${sid}/var_redirect_dns_port" ] && nft "add rule $NFTABLE_NAME PSW2_REDIRECT ip protocol udp ${_ipt_source} udp dport 53 counter redirect to $(cat ${TMP_ACL_PATH}/${sid}/var_redirect_dns_port) comment \"$remarks\""
					msg2="${msg}使用 TCP 节点[$node_remark]"
					if [ -n "${is_tproxy}" ]; then
						msg2="${msg2}(TPROXY:${redir_port})"
						nft_chain="PSW2_MANGLE"
						nft_j="counter jump PSW2_RULE"
					else
						msg2="${msg2}(REDIRECT:${redir_port})"
						nft_chain="PSW2_NAT"
						nft_j="$(REDIRECT $redir_port)"
					fi

					[ "${write_ipset_direct}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_NAT ip protocol tcp ${_ipt_source} ip daddr @$nftset_whitelist counter return comment \"$remarks\""
					[ "${write_ipset_direct}" = "1" ] && [ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp ${_ipt_source} ip daddr @$nftset_whitelist counter return comment \"$remarks\""

					[ "$accept_icmp" = "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr $FAKE_IP $(REDIRECT) comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} $(REDIRECT) comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} return comment \"$remarks\""
					}

					[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr $FAKE_IP_6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} $(REDIRECT) comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} return comment \"$remarks\"" 2>/dev/null
					}

					nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} ip daddr $FAKE_IP ${nft_j} comment \"$remarks\""
					nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ${nft_j} comment \"$remarks\""
					[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY4) comment \"$remarks\""

					[ "$PROXY_IPV6" == "1" ] && {
						[ "${write_ipset_direct}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} ip6 daddr @$nftset_whitelist6 counter return comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} ip6 daddr $FAKE_IP_6 counter jump PSW2_RULE comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") counter jump PSW2_RULE comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY) comment \"$remarks\"" 2>/dev/null
					}
					echolog "  - ${msg2}"
				}
				nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} counter return comment \"$remarks\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null

				[ "$udp_proxy_mode" != "disable" ] && [ -n "$redir_port" ] && {
					msg2="${msg}使用 UDP 节点[$node_remark](TPROXY:${redir_port})"

					[ "${write_ipset_direct}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} ip daddr @$nftset_whitelist counter return comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} ip daddr $FAKE_IP counter jump PSW2_RULE comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW2_RULE comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(REDIRECT $redir_port TPROXY4) comment \"$remarks\""

					[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
						[ "${write_ipset_direct}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} ip6 daddr @$nftset_whitelist6 counter return comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} ip6 daddr $FAKE_IP_6 counter jump PSW2_RULE comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW2_RULE comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} $(REDIRECT $redir_port TPROXY) comment \"$remarks\"" 2>/dev/null
					}
					echolog "  - ${msg2}"
				}
				nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} counter return comment \"$remarks\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null
				unset nft_chain nft_j _ipt_source msg msg2
			done
			unset enabled sid remarks sources tcp_proxy_mode udp_proxy_mode tcp_no_redir_ports udp_no_redir_ports tcp_redir_ports udp_redir_ports node interface
			unset redir_port node_remark _acl_list
		done
	}

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && [ "$CLIENT_PROXY" == 1 ] && {
		#  加载默认代理模式
		msg="【默认】，"

		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return comment \"默认\""
			if [ "$TCP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				TCP_PROXY_MODE="disable"
				echolog "  - ${msg}不代理所有 TCP 端口"
			fi
		}

		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add $NFTABLE_NAME PSW2_MANGLE ip protocol udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return comment \"默认\""
			nft "add $NFTABLE_NAME PSW2_MANGLE_V6 counter meta l4proto udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return comment \"默认\""
			if [ "$UDP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				UDP_PROXY_MODE="disable"
				echolog "  - ${msg}不代理所有 UDP 端口"
			fi
		}

		if [ "$TCP_PROXY_MODE" != "disable" ] && [ "$NODE" != "nil" ]; then
			msg2="${msg}使用 TCP 节点[$(config_n_get $NODE remarks)]"
			if [ -n "${is_tproxy}" ]; then
				msg2="${msg2}(TPROXY:${REDIR_PORT})"
				nft_chain="PSW2_MANGLE"
				nft_j="counter jump PSW2_RULE"
			else
				msg2="${msg2}(REDIRECT:${REDIR_PORT})"
				nft_chain="PSW2_NAT"
				nft_j="$(REDIRECT $REDIR_PORT)"
			fi

			[ "${WRITE_IPSET_DIRECT}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_NAT ip protocol tcp ip daddr @$nftset_global_whitelist counter return comment \"默认\""
			[ "${WRITE_IPSET_DIRECT}" = "1" ] && [ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp ip daddr @$nftset_global_whitelist counter return comment \"默认\""

			[ "$accept_icmp" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ip daddr $FAKE_IP $(REDIRECT) comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp $(REDIRECT) comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp return comment \"默认\""
			}

			[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr $FAKE_IP_6 $(REDIRECT) comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 $(REDIRECT) comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 return comment \"默认\""
			}

			nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr $FAKE_IP ${nft_j} comment \"默认\""
			nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j} comment \"默认\""
			[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp $(REDIRECT $REDIR_PORT TPROXY4) comment \"默认\""

			[ "$PROXY_IPV6" == "1" ] && {
				[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ip6 daddr @$nftset_global_whitelist6 counter return comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ip6 daddr $FAKE_IP_6 jump PSW2_RULE comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW2_RULE comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp $(REDIRECT $REDIR_PORT TPROXY) comment \"默认\""
			}

			echolog "${msg2}"
		fi

		if [ "$UDP_PROXY_MODE" != "disable" ] && [ "$NODE" != "nil" ]; then
			msg2="${msg}使用 UDP 节点[$(config_n_get $NODE remarks)](TPROXY:${REDIR_PORT})"

			[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ip daddr @$nftset_global_whitelist counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW2_RULE comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW2_RULE comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp $(REDIRECT $REDIR_PORT TPROXY4) comment \"默认\""

			[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
				[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ip6 daddr @$nftset_global_whitelist6 counter return comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ip6 daddr $FAKE_IP_6 jump PSW2_RULE comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW2_RULE comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp $(REDIRECT $REDIR_PORT TPROXY) comment \"默认\""
			}

			echolog "${msg2}"
			udp_flag=1
		fi
	}
}

filter_haproxy() {
	for item in $(uci show $CONFIG | grep ".lbss=" | cut -d "'" -f 2); do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		[ -n "$ip" ] && insert_nftset $NFTSET_VPSLIST "-1" $ip
	done
	echolog "加入负载均衡的节点到nftset[$NFTSET_VPSLIST]直连完成"
}

filter_vps_addr() {
	for server_host in $@; do
		local vps_ip4=$(get_host_ip "ipv4" ${server_host})
		local vps_ip6=$(get_host_ip "ipv6" ${server_host})
		[ -n "$vps_ip4" ] && insert_nftset $NFTSET_VPSLIST "-1" $vps_ip4
		[ -n "$vps_ip6" ] && insert_nftset $NFTSET_VPSLIST6 "-1" $vps_ip6
	done
}

filter_vpsip() {
	insert_nftset $NFTSET_VPSLIST "-1" $(uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -v "^127\.0\.0\.1$" | sed -e "/^$/d")
	echolog "  - [$?]加入所有IPv4节点到nftset[$NFTSET_VPSLIST]直连完成"
	insert_nftset $NFTSET_VPSLIST6 "-1" $(uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d")
	echolog "  - [$?]加入所有IPv6节点到nftset[$NFTSET_VPSLIST6]直连完成"
}

filter_node() {
	local proxy_node=${1}
	local stream=$(echo ${2} | tr 'A-Z' 'a-z')
	local proxy_port=${3}

	filter_rules() {
		local node=${1}
		local stream=${2}
		local _proxy=${3}
		local _port=${4}
		local _is_tproxy msg msg2

		if [ -n "$node" ] && [ "$node" != "nil" ]; then
			local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
			local address=$(config_n_get $node address)
			local port=$(config_n_get $node port)
			_is_tproxy=${is_tproxy}
			[ "$stream" == "udp" ] && _is_tproxy="TPROXY"
			if [ -n "${_is_tproxy}" ]; then
				msg="TPROXY"
			else
				msg="REDIRECT"
			fi
		else
			echolog "  - 节点配置不正常，略过"
			return 0
		fi

		local ADD_INDEX=$FORCE_INDEX
		for _ipt in 4 6; do
			[ "$_ipt" == "4" ] && _ip_type=ip && _set_name=$NFTSET_VPSLIST
			[ "$_ipt" == "6" ] && _ip_type=ip6 && _set_name=$NFTSET_VPSLIST6
			nft "list chain $NFTABLE_NAME $nft_output_chain" 2>/dev/null | grep -q "${address}:${port}"
			if [ $? -ne 0 ]; then
				unset dst_rule
				local dst_rule="jump PSW2_RULE"
				msg2="按规则路由(${msg})"
				[ -n "${is_tproxy}" ] || {
					dst_rule=$(REDIRECT $_port)
					msg2="套娃使用(${msg}:${port} -> ${_port})"
				}
				[ -n "$_proxy" ] && [ "$_proxy" == "1" ] && [ -n "$_port" ] || {
					ADD_INDEX=$(RULE_LAST_INDEX "$NFTABLE_NAME" $nft_output_chain $_set_name $FORCE_INDEX)
					dst_rule="return"
					msg2="直连代理"
				}
				nft "insert rule $NFTABLE_NAME $nft_output_chain position $ADD_INDEX meta l4proto $stream $_ip_type daddr $address $stream dport $port $dst_rule comment \"${address}:${port}\"" 2>/dev/null
			else
				msg2="已配置过的节点，"
			fi
		done
		msg="[$?]$(echo ${2} | tr 'a-z' 'A-Z')${msg2}使用链${ADD_INDEX}，节点（${type}）：${address}:${port}"
		#echolog "  - ${msg}"
	}

	local proxy_protocol=$(config_n_get $proxy_node protocol)
	local proxy_type=$(echo $(config_n_get $proxy_node type nil) | tr 'A-Z' 'a-z')
	[ "$proxy_type" == "nil" ] && echolog "  - 节点配置不正常，略过！：${proxy_node}" && return 0
	if [ "$proxy_protocol" == "_balancing" ]; then
		#echolog "  - 多节点负载均衡（${proxy_type}）..."
		proxy_node=$(config_n_get $proxy_node balancing_node)
		for _node in $proxy_node; do
			filter_rules "$_node" "$stream"
		done
	elif [ "$proxy_protocol" == "_shunt" ]; then
		#echolog "  - 按请求目的地址分流（${proxy_type}）..."
		local default_node=$(config_n_get $proxy_node default_node _direct)
		local main_node=$(config_n_get $proxy_node main_node nil)
		if [ "$main_node" != "nil" ]; then
			filter_rules $main_node $stream
		else
			if [ "$default_node" != "_direct" ] && [ "$default_node" != "_blackhole" ]; then
				filter_rules $default_node $stream
			fi
		fi
:<<!
		local default_node_address=$(get_host_ip ipv4 $(config_n_get $default_node address) 1)
		local default_node_port=$(config_n_get $default_node port)

		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			#local shunt_proxy=$(config_n_get $proxy_node "${shunt_id}_proxy" 0)
			local shunt_proxy=0
			local shunt_node=$(config_n_get $proxy_node "${shunt_id}" nil)
			[ "$shunt_node" != "nil" ] && {
				[ "$shunt_proxy" == 1 ] && {
					local shunt_node_address=$(get_host_ip ipv4 $(config_n_get $shunt_node address) 1)
					local shunt_node_port=$(config_n_get $shunt_node port)
					[ "$shunt_node_address" == "$default_node_address" ] && [ "$shunt_node_port" == "$default_node_port" ] && {
						shunt_proxy=0
					}
				}
				filter_rules "$(config_n_get $proxy_node $shunt_id)" "$stream" "$shunt_proxy" "$proxy_port"
			}
		done
!
	else
		#echolog "  - 普通节点（${proxy_type}）..."
		filter_rules "$proxy_node" "$stream"
	fi
}

dns_hijack() {
	[ $(config_t_get global dns_redirect "0") = "1" ] && {
		nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp udp dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp tcp dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp udp dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp tcp dport 53 counter return"
		nft insert rule $NFTABLE_NAME dstnat position 0 tcp dport 53 counter redirect to :53 comment \"PSW2_DNS_Hijack\" 2>/dev/null
		nft insert rule $NFTABLE_NAME dstnat position 0 udp dport 53 counter redirect to :53 comment \"PSW2_DNS_Hijack\" 2>/dev/null
		nft insert rule $NFTABLE_NAME dstnat position 0 meta nfproto {ipv6} tcp dport 53 counter redirect to :53 comment \"PSW2_DNS_Hijack\" 2>/dev/null
		nft insert rule $NFTABLE_NAME dstnat position 0 meta nfproto {ipv6} udp dport 53 counter redirect to :53 comment \"PSW2_DNS_Hijack\" 2>/dev/null
		uci -q set dhcp.@dnsmasq[0].dns_redirect='0' 2>/dev/null
		uci commit dhcp 2>/dev/null
		echolog "  - 开启 DNS 重定向"
	}
}

add_firewall_rule() {
	echolog "开始加载防火墙规则..."
	gen_nft_tables
	gen_nftset $NFTSET_LANLIST ipv4_addr 0 "-1" $(gen_lanlist)
	gen_nftset $NFTSET_VPSLIST ipv4_addr 0 0

	gen_nftset $NFTSET_LANLIST6 ipv6_addr 0 "-1" $(gen_lanlist_6)
	gen_nftset $NFTSET_VPSLIST6 ipv6_addr 0 0

	# 忽略特殊IP段
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#echolog "本机IPv4网段互访直连：${lan_ip}"
		#echolog "本机IPv6网段互访直连：${lan_ip6}"

		[ -n "$lan_ip" ] && insert_nftset $NFTSET_LANLIST "-1" $(echo $lan_ip | sed -e "s/ /\n/g")
		[ -n "$lan_ip6" ] && insert_nftset $NFTSET_LANLIST6 "-1" $(echo $lan_ip6 | sed -e "s/ /\n/g")
	}

	[ -n "$ISP_DNS" ] && {
		#echolog "处理 ISP DNS 例外..."
		for ispip in $ISP_DNS; do
			insert_nftset $NFTSET_LANLIST "-1" $ispip
			echolog "  - [$?]追加ISP IPv4 DNS到白名单：${ispip}"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		#echolog "处理 ISP IPv6 DNS 例外..."
		for ispip6 in $ISP_DNS6; do
			insert_nftset $NFTSET_LANLIST6 "-1" $ispip6
			echolog "  - [$?]追加ISP IPv6 DNS到白名单：${ispip6}"
		done
	}
	
	local nftset_global_whitelist="passwall2_global_whitelist"
	local nftset_global_whitelist6="passwall2_global_whitelist6"
	gen_nftset $nftset_global_whitelist ipv4_addr 0 0
	gen_nftset $nftset_global_whitelist6 ipv6_addr 0 0

	#分流规则的IP列表(使用分流节点时导入)
	local USE_SHUNT_NODE=0
	NODE_PROTOCOL=$(config_n_get $NODE protocol)
	[ "$NODE_PROTOCOL" = "_shunt" ] && USE_SHUNT_NODE=1
	[ "$USE_SHUNT_NODE" = "1" ] && {
		local SHUNT_DEFAULT_NODE=$(config_n_get $NODE default_node _direct)
		local GEOIP_CODE=""
		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			local SHUNT_RULE_NODE=$(config_n_get $NODE ${shunt_id} nil)
			[ "${SHUNT_RULE_NODE}" == "_default" ] && SHUNT_RULE_NODE=${SHUNT_DEFAULT_NODE}
			[ "${SHUNT_RULE_NODE}" == "_direct" ] && {
				insert_nftset $ipset_global_whitelist "0" $(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
				insert_nftset $ipset_global_whitelist6 "0" $(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
				[ "$(config_t_get global_rules enable_geoview)" = "1" ] && {
					local geoip_code=$(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
					[ -n "$geoip_code" ] && GEOIP_CODE="${GEOIP_CODE:+$GEOIP_CODE,}$geoip_code"
				}
			}
		done
	}

	if [ -n "$GEOIP_CODE" ] && type geoview &> /dev/null; then
		insert_nftset $ipset_global_whitelist "0" $(get_geoip $GEOIP_CODE ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
		insert_nftset $ipset_global_whitelist6 "0" $(get_geoip $GEOIP_CODE ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		echolog "  - [$?]解析并加入分流节点 GeoIP 到 IPSET 完成"
	fi

	#  过滤所有节点IP
	filter_vpsip > /dev/null 2>&1 &
	filter_haproxy > /dev/null 2>&1 &
	# Prevent some conditions
	filter_vps_addr $(config_n_get $NODE address) > /dev/null 2>&1 &
	filter_vps_addr $(config_n_get $NODE download_address) > /dev/null 2>&1 &

	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	local tcp_proxy_way=$(config_t_get global_forwarding tcp_proxy_way redirect)
	if [ "$tcp_proxy_way" = "redirect" ]; then
		unset is_tproxy
		nft_prerouting_chain="PSW2_NAT"
		nft_output_chain="PSW2_OUTPUT_NAT"
	elif [ "$tcp_proxy_way" = "tproxy" ]; then
		is_tproxy="TPROXY"
		nft_prerouting_chain="PSW2_MANGLE"
		nft_output_chain="PSW2_OUTPUT_MANGLE"
	fi

	nft "add chain $NFTABLE_NAME PSW2_DIVERT"
	nft "flush chain $NFTABLE_NAME PSW2_DIVERT"
	nft "add rule $NFTABLE_NAME PSW2_DIVERT meta l4proto tcp socket transparent 1 mark set 1 counter accept"

	nft "add chain $NFTABLE_NAME PSW2_REDIRECT"
	nft "flush chain $NFTABLE_NAME PSW2_REDIRECT"
	nft "add rule $NFTABLE_NAME dstnat jump PSW2_REDIRECT"

	# for ipv4 ipv6 tproxy mark
	nft "add chain $NFTABLE_NAME PSW2_RULE"
	nft "flush chain $NFTABLE_NAME PSW2_RULE"
	nft "add rule $NFTABLE_NAME PSW2_RULE meta mark set ct mark counter"
	nft "add rule $NFTABLE_NAME PSW2_RULE meta mark 1 counter return"
	nft "add rule $NFTABLE_NAME PSW2_RULE tcp flags &(fin|syn|rst|ack) == syn meta mark set mark and 0x0 xor 0x1 counter"
	nft "add rule $NFTABLE_NAME PSW2_RULE meta l4proto udp ct state new meta mark set mark and 0x0 xor 0x1 counter"
	nft "add rule $NFTABLE_NAME PSW2_RULE ct mark set mark counter"

	#ipv4 tproxy mode and udp
	nft "add chain $NFTABLE_NAME PSW2_MANGLE"
	nft "flush chain $NFTABLE_NAME PSW2_MANGLE"
	nft "add rule $NFTABLE_NAME PSW2_MANGLE ip daddr @$NFTSET_LANLIST counter return"
	nft "add rule $NFTABLE_NAME PSW2_MANGLE ip daddr @$NFTSET_VPSLIST counter return"

	nft "add chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE"
	nft "flush chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip daddr @$NFTSET_LANLIST counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip daddr @$NFTSET_VPSLIST counter return"
	[ -n "$AUTO_DNS" ] && {
		for auto_dns in $(echo $AUTO_DNS | tr ',' ' '); do
			local dns_address=$(echo $auto_dns | awk -F '#' '{print $1}')
			local dns_port=$(echo $auto_dns | awk -F '#' '{print $2}')
			nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp ip daddr ${dns_address} $(factor ${dns_port:-53} "udp dport") counter return"
			echolog "  - [$?]追加直连DNS到nftables：${dns_address}:${dns_port:-53}"
		done
	}
	[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip daddr @$nftset_global_whitelist counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE meta mark 0xff counter return"

	# jump chains
	nft "add rule $NFTABLE_NAME mangle_prerouting ip protocol udp counter jump PSW2_MANGLE"
	[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME mangle_prerouting ip protocol tcp counter jump PSW2_MANGLE"
	insert_rule_before "$NFTABLE_NAME" "mangle_prerouting" "PSW2_MANGLE" "counter jump PSW2_DIVERT"

	#ipv4 tcp redirect mode
	[ -z "${is_tproxy}" ] && {
		nft "add chain $NFTABLE_NAME PSW2_NAT"
		nft "flush chain $NFTABLE_NAME PSW2_NAT"
		nft "add rule $NFTABLE_NAME PSW2_NAT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule $NFTABLE_NAME PSW2_NAT ip daddr @$NFTSET_VPSLIST counter return"
		nft "add rule $NFTABLE_NAME dstnat ip protocol tcp counter jump PSW2_NAT"

		nft "add chain $NFTABLE_NAME PSW2_OUTPUT_NAT"
		nft "flush chain $NFTABLE_NAME PSW2_OUTPUT_NAT"
		nft "add rule $NFTABLE_NAME PSW2_OUTPUT_NAT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule $NFTABLE_NAME PSW2_OUTPUT_NAT ip daddr @$NFTSET_VPSLIST counter return"
		[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_OUTPUT_NAT ip daddr @$nftset_global_whitelist counter return"
		nft "add rule $NFTABLE_NAME PSW2_OUTPUT_NAT meta mark 0xff counter return"
	}

	#icmp ipv6-icmp redirect
	if [ "$accept_icmp" = "1" ]; then
		nft "add chain $NFTABLE_NAME PSW2_ICMP_REDIRECT"
		nft "flush chain $NFTABLE_NAME PSW2_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip daddr @$NFTSET_VPSLIST counter return"
		[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip daddr @$nftset_global_whitelist counter return"

		[ "$accept_icmpv6" = "1" ] && {
			nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip6 daddr @$NFTSET_LANLIST6 counter return"
			nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip6 daddr @$NFTSET_VPSLIST6 counter return"
			[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip6 daddr @$nftset_global_whitelist6 counter return"
		}

		nft "add rule $NFTABLE_NAME dstnat meta l4proto {icmp,icmpv6} counter jump PSW2_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME nat_output meta l4proto {icmp,icmpv6} counter jump PSW2_ICMP_REDIRECT"
	fi

	WAN_IP=$(get_wan_ip)
	if [ -n "${WAN_IP}" ]; then
		nft "add rule $NFTABLE_NAME PSW2_MANGLE ip daddr ${WAN_IP} counter return comment \"WAN_IP_RETURN\""
		[ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_NAT ip daddr ${WAN_IP} counter return comment \"WAN_IP_RETURN\""
	fi
	unset WAN_IP

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	#ipv6 tproxy mode and udp
	nft "add chain $NFTABLE_NAME PSW2_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW2_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ip6 daddr @$NFTSET_LANLIST6 counter return"
	nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ip6 daddr @$NFTSET_VPSLIST6 counter return"
	[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ip6 daddr @$nftset_global_whitelist6 counter return"

	nft "add chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_LANLIST6 counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_VPSLIST6 counter return"
	[ "${WRITE_IPSET_DIRECT}" = "1" ] && nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip6 daddr @$nftset_global_whitelist6 counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta mark 0xff counter return"

	# jump chains
	[ "$PROXY_IPV6" == "1" ] && {
		nft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto {ipv6} counter jump PSW2_MANGLE_V6"
		nft "add rule $NFTABLE_NAME mangle_output meta nfproto {ipv6} counter jump PSW2_OUTPUT_MANGLE_V6 comment \"PSW2_OUTPUT_MANGLE\""

		WAN6_IP=$(get_wan6_ip)
		[ -n "${WAN6_IP}" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ip6 daddr ${WAN6_IP} counter return comment \"WAN6_IP_RETURN\""
		unset WAN6_IP

		ip -6 rule add fwmark 1 table 100
		ip -6 route add local ::/0 dev lo table 100
	}
	
	# 过滤Socks节点
	[ "$SOCKS_ENABLED" = "1" ] && {
		local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		#echolog "分析 Socks 服务所使用节点..."
		local id enabled node port msg num
		for id in $ids; do
			enabled=$(config_n_get $id enabled 0)
			[ "$enabled" == "1" ] || continue
			node=$(config_n_get $id node nil)
			port=$(config_n_get $id port 0)
			msg="Socks 服务 [:${port}]"
			if [ "$node" == "nil" ] || [ "$port" == "0" ]; then
				msg="${msg} 未配置完全，略过"
			else
				filter_node $node TCP > /dev/null 2>&1 &
				filter_node $node UDP > /dev/null 2>&1 &
			fi
			#echolog "  - ${msg}"
		done
	}

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
		# 过滤节点
		filter_node $NODE TCP > /dev/null 2>&1 &
		filter_node $NODE UDP > /dev/null 2>&1 &

		TCP_LOCALHOST_PROXY=$LOCALHOST_PROXY
		UDP_LOCALHOST_PROXY=$LOCALHOST_PROXY
		
		msg="【路由器本机】，"
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return"
			nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return"
			if [ "$TCP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				unset TCP_LOCALHOST_PROXY
				echolog "  - ${msg}不代理所有 TCP"
			fi
		}
		
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return"
			nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return"
			if [ "$UDP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				unset UDP_LOCALHOST_PROXY
				echolog "  - ${msg}不代理所有 UDP"
			fi
		}
	
		# 加载路由器自身代理 TCP
		if [ "$NODE" != "nil" ] && [ "$TCP_LOCALHOST_PROXY" = "1" ]; then
			[ "$accept_icmp" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp ip daddr $FAKE_IP counter redirect"
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp counter redirect"
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp counter return"
			}

			[ "$accept_icmpv6" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr $FAKE_IP_6 counter redirect"
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter redirect"
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter return"
			}

			if [ -n "${is_tproxy}" ]; then
				nft_chain="PSW2_OUTPUT_MANGLE"
				nft_j="counter jump PSW2_RULE"
			else
				nft_chain="PSW2_OUTPUT_NAT"
				nft_j="$(REDIRECT $REDIR_PORT)"
			fi

			nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr $FAKE_IP ${nft_j}"
			nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j}"
			[ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME nat_output ip protocol tcp counter jump PSW2_OUTPUT_NAT"
			[ -n "${is_tproxy}" ] && {
				nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp iif lo $(REDIRECT $REDIR_PORT TPROXY4) comment \"本机\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp iif lo counter return comment \"本机\""
				nft "add rule $NFTABLE_NAME mangle_output ip protocol tcp counter jump PSW2_OUTPUT_MANGLE comment \"PSW2_OUTPUT_MANGLE\""
			}

			[ "$PROXY_IPV6" == "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr $FAKE_IP_6 jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp iif lo $(REDIRECT $REDIR_PORT TPROXY) comment \"本机\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp iif lo counter return comment \"本机\""
			}

			for iface in $(ls ${TMP_IFACE_PATH}); do
				nft "insert rule $NFTABLE_NAME $nft_output_chain ip protocol tcp oif $iface counter return"
				nft "insert rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip protocol tcp oif $iface counter return"
			done
		fi

		# 加载路由器自身代理 UDP
		if [ "$NODE" != "nil" ] && [ "$UDP_LOCALHOST_PROXY" = "1" ]; then
			nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW2_RULE"
			nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW2_RULE"
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp iif lo $(REDIRECT $REDIR_PORT TPROXY4) comment \"本机\""
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp iif lo counter return comment \"本机\""
			nft "add rule $NFTABLE_NAME mangle_output ip protocol udp counter jump PSW2_OUTPUT_MANGLE comment \"PSW2_OUTPUT_MANGLE\""

			if [ "$PROXY_IPV6_UDP" == "1" ]; then
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr $FAKE_IP_6 jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp iif lo $(REDIRECT $REDIR_PORT TPROXY) comment \"本机\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp iif lo counter return comment \"本机\""
			fi

			for iface in $(ls ${TMP_IFACE_PATH}); do
				nft "insert rule $NFTABLE_NAME $nft_output_chain ip protocol udp oif $iface counter return"
				nft "insert rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip protocol udp oif $iface counter return"
			done
		fi

		nft "add rule $NFTABLE_NAME mangle_output oif lo counter return comment \"PSW2_OUTPUT_MANGLE\""
		nft "add rule $NFTABLE_NAME mangle_output meta mark 1 counter return comment \"PSW2_OUTPUT_MANGLE\""

		nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp udp dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp udp dport 53 counter return"
	}

	#  加载ACLS
	load_acl

	[ -n "${is_tproxy}" -o -n "${udp_flag}" ] && {
		bridge_nf_ipt=$(sysctl -e -n net.bridge.bridge-nf-call-iptables)
		echo -n $bridge_nf_ipt > $TMP_PATH/bridge_nf_ipt
		sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
		[ "$PROXY_IPV6" == "1" ] && {
			bridge_nf_ip6t=$(sysctl -e -n net.bridge.bridge-nf-call-ip6tables)
			echo -n $bridge_nf_ip6t > $TMP_PATH/bridge_nf_ip6t
			sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
		}
	}
	echolog "防火墙规则加载完成！"
}

del_firewall_rule() {
	for nft in "dstnat" "srcnat" "nat_output" "mangle_prerouting" "mangle_output"; do
        local handles=$(nft -a list chain $NFTABLE_NAME ${nft} 2>/dev/null | grep -E "PSW2_" | awk -F '# handle ' '{print$2}')
		for handle in $handles; do
			nft delete rule $NFTABLE_NAME ${nft} handle ${handle} 2>/dev/null
		done
	done

	for handle in $(nft -a list chains | grep -E "chain PSW2_" | grep -v "PSW2_RULE" | awk -F '# handle ' '{print$2}'); do
		nft delete chain $NFTABLE_NAME handle ${handle} 2>/dev/null
	done

	# Need to be removed at the end, otherwise it will show "Resource busy"
	nft delete chain $NFTABLE_NAME handle $(nft -a list chains | grep -E "PSW2_RULE" | awk -F '# handle ' '{print$2}') 2>/dev/null

	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ip -6 rule del fwmark 1 table 100 2>/dev/null
	ip -6 route del local ::/0 dev lo table 100 2>/dev/null

	destroy_nftset $NFTSET_LANLIST
	destroy_nftset $NFTSET_VPSLIST

	destroy_nftset $NFTSET_LANLIST6
	destroy_nftset $NFTSET_VPSLIST6

	$DIR/app.sh echolog "删除nftables防火墙规则完成。"
}

flush_nftset() {
	$DIR/app.sh echolog "清空 NFTSET。"
	for _name in $(nft -a list sets | grep -E "passwall2" | awk -F 'set ' '{print $2}' | awk '{print $1}'); do
		destroy_nftset ${_name}
	done
}

flush_table() {
	nft flush table $NFTABLE_NAME
	nft delete table $NFTABLE_NAME
}

flush_nftset_reload() {
	del_firewall_rule
	flush_table
	rm -rf /tmp/singbox_passwall2_*
	/etc/init.d/passwall2 reload
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	local nft_chain_file=$TMP_PATH/PSW2_RULE.nft
	echo '#!/usr/sbin/nft -f' > $nft_chain_file
	nft list table $NFTABLE_NAME >> $nft_chain_file

	local __nft=" "
	__nft=$(cat <<- EOF
		[ -z "\$(nft list chain $NFTABLE_NAME mangle_prerouting | grep PSW2_DIVERT)" ] && nft -f ${nft_chain_file}
		[ -z "${is_tproxy}" ] && {
			PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "$NFTABLE_NAME" PSW2_NAT WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN_IP=\$(sh ${MY_PATH} get_wan_ip)
				[ ! -z "\${WAN_IP}" ] && nft "replace rule $NFTABLE_NAME PSW2_NAT handle \$PR_INDEX ip daddr "\${WAN_IP}" counter return comment \"WAN_IP_RETURN\""
			fi
		}

		PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "$NFTABLE_NAME" PSW2_MANGLE WAN_IP_RETURN -1)
		if [ \$PR_INDEX -ge 0 ]; then
			WAN_IP=\$(sh ${MY_PATH} get_wan_ip)
			[ ! -z "\${WAN_IP}" ] && nft "replace rule $NFTABLE_NAME PSW2_MANGLE handle \$PR_INDEX ip daddr "\${WAN_IP}" counter return comment \"WAN_IP_RETURN\""
		fi

		[ "$PROXY_IPV6" == "1" ] && {
			PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "$NFTABLE_NAME" PSW2_MANGLE_V6 WAN6_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN6_IP=\$(sh ${MY_PATH} get_wan6_ip)
				[ ! -z "\${WAN_IP}" ] && nft "replace rule $NFTABLE_NAME PSW2_MANGLE_V6 handle \$PR_INDEX ip6 daddr "\${WAN6_IP}" counter return comment \"WAN6_IP_RETURN\""
			fi
		}
	EOF
	)

	cat <<-EOF >> $FWI
	${__nft}
	EOF
	return 0
}

start() {
	[ "$ENABLED_DEFAULT_ACL" == 0 -a "$ENABLED_ACLS" == 0 ] && return
	add_firewall_rule
	gen_include
}

stop() {
	del_firewall_rule
	flush_include
}

arg1=$1
shift
case $arg1 in
RULE_LAST_INDEX)
	RULE_LAST_INDEX "$@"
	;;
insert_rule_before)
	insert_rule_before "$@"
	;;
insert_rule_after)
	insert_rule_after "$@"
	;;
flush_nftset)
	flush_nftset
	;;
flush_nftset_reload)
	flush_nftset_reload
	;;
get_wan_ip)
	get_wan_ip
	;;
get_wan6_ip)
	get_wan6_ip
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
