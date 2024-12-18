#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/nftables.sh
NFTABLE_NAME="inet passwall2"
NFTSET_LOCALLIST="passwall2_locallist"
NFTSET_LANLIST="passwall2_lanlist"
NFTSET_VPSLIST="passwall2_vpslist"

NFTSET_LOCALLIST6="passwall2_locallist6"
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

gen_shunt_list() {
	local node=${1}
	local shunt_list4_var_name=${2}
	local shunt_list6_var_name=${3}
	local _write_ipset_direct=${4}
	local _set_name4=${5}
	local _set_name6=${6}
	[ -z "$node" ] && continue
	unset ${shunt_list4_var_name}
	unset ${shunt_list6_var_name}
	local _SHUNT_LIST4 _SHUNT_LIST6
	local USE_SHUNT_NODE=0
	NODE_PROTOCOL=$(config_n_get $node protocol)
	[ "$NODE_PROTOCOL" = "_shunt" ] && USE_SHUNT_NODE=1
	[ "$USE_SHUNT_NODE" = "1" ] && {
		local default_node=$(config_n_get ${node} default_node _direct)
		local default_outbound="redirect"
		[ "$default_node" = "_direct" ] && default_outbound="direct"
		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			local shunt_node=$(config_n_get ${node} "${shunt_id}")
			[ -n "$shunt_node" ] && {
				local nftset_v4="passwall2_${node}_${shunt_id}"
				local nftset_v6="passwall2_${node}_${shunt_id}6"
				gen_nftset $nftset_v4 ipv4_addr 0 0
				gen_nftset $nftset_v6 ipv6_addr 0 0
				local outbound="redirect"
				[ "$shunt_node" = "_direct" ] && outbound="direct"
				[ "$shunt_node" = "_default" ] && outbound="${default_outbound}"
				_SHUNT_LIST4="${_SHUNT_LIST4} ${nftset_v4}:${outbound}"
				_SHUNT_LIST6="${_SHUNT_LIST6} ${nftset_v6}:${outbound}"
				insert_nftset $nftset_v4 "0" $(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
				insert_nftset $nftset_v6 "0" $(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
				[ "$(config_t_get global_rules enable_geoview)" = "1" ] && {
					local _geoip_code=$(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
					[ -n "$_geoip_code" ] && {
						if [ "$(config_n_get $node type)" = "sing-box" ]; then
							insert_nftset $nftset_v4 "0" $(get_singbox_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
							insert_nftset $nftset_v6 "0" $(get_singbox_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
						else
							if type geoview &> /dev/null; then
								insert_nftset $nftset_v4 "0" $(get_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
								insert_nftset $nftset_v6 "0" $(get_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
							fi
						fi
						echolog "  - [$?]解析分流规则[$shunt_id]-[geoip:${_geoip_code}]加入到 NFTSET 完成"
					}
				}
			}
		done
		[ "${_write_ipset_direct}" = "1" ] && {
			_SHUNT_LIST4="${_SHUNT_LIST4} ${_set_name4}:direct"
			_SHUNT_LIST6="${_SHUNT_LIST6} ${_set_name6}:direct"
		}
		[ -n "$default_node" ] && {
			local nftset_v4="passwall2_${node}_default"
			local nftset_v6="passwall2_${node}_default6"
			gen_nftset $nftset_v4 ipv4_addr 0 0
			gen_nftset $nftset_v6 ipv6_addr 0 0
			_SHUNT_LIST4="${_SHUNT_LIST4} ${nftset_v4}:${default_outbound}"
			_SHUNT_LIST6="${_SHUNT_LIST6} ${nftset_v6}:${default_outbound}"
		}
	}
	[ -n "${_SHUNT_LIST4}" ] && eval ${shunt_list4_var_name}=\"${_SHUNT_LIST4}\"
	[ -n "${_SHUNT_LIST6}" ] && eval ${shunt_list6_var_name}=\"${_SHUNT_LIST6}\"
}

add_shunt_t_rule() {
	local shunt_args=${1}
	local t_args=${2}
	local t_jump_args=${3}
	local t_comment=${4}
	[ -n "${shunt_args}" ] && {
		[ -n "${t_comment}" ] && t_comment="comment \"$t_comment\""
		for j in ${shunt_args}; do
			local _set_name=$(echo ${j} | awk -F ':' '{print $1}')
			local _outbound=$(echo ${j} | awk -F ':' '{print $2}')
			[ -n "${_set_name}" ] && [ -n "${_outbound}" ] && {
				local _t_arg="${t_jump_args}"
				[ "${_outbound}" = "direct" ] && _t_arg="counter return"
				${t_args} @${_set_name} ${_t_arg} ${t_comment}
			}
		done
	}
}

load_acl() {
	[ "$ENABLED_ACLS" == 1 ] && {
		echolog "访问控制："
		acl_app
		for sid in $(ls -F ${TMP_ACL_PATH} | grep '/$' | awk -F '/' '{print $1}' | grep -v 'default'); do
			eval $(uci -q show "${CONFIG}.${sid}" | cut -d'.' -sf 3-)

			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			tcp_proxy_mode="global"
			udp_proxy_mode="global"
			tcp_redir_ports=${tcp_redir_ports:-default}
			udp_redir_ports=${udp_redir_ports:-default}
			node=${node:-default}
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			[ "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
			[ "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS

			[ -n "$(get_cache_var "ACL_${sid}_node")" ] && node=$(get_cache_var "ACL_${sid}_node")
			[ -n "$(get_cache_var "ACL_${sid}_redir_port")" ] && redir_port=$(get_cache_var "ACL_${sid}_redir_port")
			[ -n "$(get_cache_var "ACL_${sid}_dns_port")" ] && dns_redirect_port=$(get_cache_var "ACL_${sid}_dns_port")
			[ -n "$node" ] && node_remark=$(config_n_get $node remarks)

			write_ipset_direct=${write_ipset_direct:-1}
			[ "${write_ipset_direct}" = "1" ] && {
				if [ -n "$(get_cache_var "ACL_${sid}_default")" ]; then
					local nftset_whitelist=${nftset_global_whitelist}
					local nftset_whitelist6=${nftset_global_whitelist6}
					shunt_list4=${SHUNT_LIST4}
					shunt_list6=${SHUNT_LIST6}
				else
					local nftset_whitelist="passwall2_${sid}_whitelist"
					local nftset_whitelist6="passwall2_${sid}_whitelist6"
					gen_nftset $nftset_whitelist ipv4_addr 3d 3d
					gen_nftset $nftset_whitelist6 ipv6_addr 3d 3d

					#分流规则的IP列表(使用分流节点时导入)
					gen_shunt_list ${node} shunt_list4 shunt_list6 ${write_ipset_direct} ${nftset_whitelist} ${nftset_whitelist6}
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

				if ([ "$tcp_proxy_mode" != "disable" ] || [ "$udp_proxy_mode" != "disable" ]) && [ -n "$dns_redirect_port" ]; then
					[ -n "$dns_redirect_port" ] && {
						nft "add rule $NFTABLE_NAME PSW2_DNS ip protocol udp ${_ipt_source} udp dport 53 counter redirect to :$dns_redirect_port comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_DNS ip protocol tcp ${_ipt_source} tcp dport 53 counter redirect to :$dns_redirect_port comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto udp ${_ipt_source} udp dport 53 counter redirect to :$dns_redirect_port comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto tcp ${_ipt_source} tcp dport 53 counter redirect to :$dns_redirect_port comment \"$remarks\""
					}
				else
					nft "add rule $NFTABLE_NAME PSW2_DNS ip protocol udp ${_ipt_source} udp dport 53 counter return comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_DNS ip protocol tcp ${_ipt_source} tcp dport 53 counter return comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto udp ${_ipt_source} udp dport 53 counter return comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto tcp ${_ipt_source} tcp dport 53 counter return comment \"$remarks\""
				fi

				[ "$tcp_proxy_mode" != "disable" ] && [ -n "$redir_port" ] && {
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

					[ "$accept_icmp" = "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr $FAKE_IP $(REDIRECT) comment \"$remarks\""
						add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr" "$(REDIRECT)" "$remarks"
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} $(REDIRECT) comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} return comment \"$remarks\""
					}

					[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr $FAKE_IP_6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr" "$(REDIRECT)" "$remarks" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} $(REDIRECT) comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} return comment \"$remarks\"" 2>/dev/null
					}

					nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} ip daddr $FAKE_IP ${nft_j} comment \"$remarks\""
					add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr" "${nft_j}" "$remarks"
					nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ${nft_j} comment \"$remarks\""
					[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY4) comment \"$remarks\""

					[ "$PROXY_IPV6" == "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} ip6 daddr $FAKE_IP_6 counter jump PSW2_RULE comment \"$remarks\""
						add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr" "counter jump PSW2_RULE" "$remarks" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") counter jump PSW2_RULE comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY) comment \"$remarks\"" 2>/dev/null
					}
					echolog "  - ${msg2}"
				}
				nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} counter return comment \"$remarks\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null

				[ "$udp_proxy_mode" != "disable" ] && [ -n "$redir_port" ] && {
					msg2="${msg}使用 UDP 节点[$node_remark](TPROXY:${redir_port})"

					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} ip daddr $FAKE_IP counter jump PSW2_RULE comment \"$remarks\""
					add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr" "counter jump PSW2_RULE" "$remarks"
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW2_RULE comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(REDIRECT $redir_port TPROXY4) comment \"$remarks\""

					[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} ip6 daddr $FAKE_IP_6 counter jump PSW2_RULE comment \"$remarks\""
						add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr" "counter jump PSW2_RULE" "$remarks"
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

		if ([ "$TCP_PROXY_MODE" != "disable" ] || [ "$UDP_PROXY_MODE" != "disable" ]) && [ -n "$NODE" ]; then
			[ -n "$DNS_REDIRECT_PORT" ] && {
				nft "add rule $NFTABLE_NAME PSW2_DNS ip protocol udp udp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_DNS ip protocol tcp tcp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto udp udp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto tcp tcp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"默认\""
			}
		fi

		if [ "$TCP_PROXY_MODE" != "disable" ] && [ -n "$NODE" ]; then
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

			[ "$accept_icmp" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ip daddr $FAKE_IP $(REDIRECT) comment \"默认\""
				add_shunt_t_rule "${SHUNT_LIST4}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ip daddr" "$(REDIRECT)" "默认"
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp $(REDIRECT) comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp return comment \"默认\""
			}

			[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr $FAKE_IP_6 $(REDIRECT) comment \"默认\""
				add_shunt_t_rule "${SHUNT_LIST6}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr" "$(REDIRECT)" "默认"
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 $(REDIRECT) comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 return comment \"默认\""
			}

			nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr $FAKE_IP ${nft_j} comment \"默认\""
			add_shunt_t_rule "${SHUNT_LIST4}" "nft add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr" "${nft_j}" "默认"
			nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j} comment \"默认\""
			[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp $(REDIRECT $REDIR_PORT TPROXY4) comment \"默认\""

			[ "$PROXY_IPV6" == "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ip6 daddr $FAKE_IP_6 jump PSW2_RULE comment \"默认\""
				add_shunt_t_rule "${SHUNT_LIST6}" "nft add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr" "${nft_j}" "默认"
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW2_RULE comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp $(REDIRECT $REDIR_PORT TPROXY) comment \"默认\""
			}

			echolog "${msg2}"
		fi

		if [ "$UDP_PROXY_MODE" != "disable" ] && [ -n "$NODE" ]; then
			msg2="${msg}使用 UDP 节点[$(config_n_get $NODE remarks)](TPROXY:${REDIR_PORT})"

			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW2_RULE comment \"默认\""
			add_shunt_t_rule "${SHUNT_LIST4}" "nft add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr" "counter jump PSW2_RULE" "默认"
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW2_RULE comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp $(REDIRECT $REDIR_PORT TPROXY4) comment \"默认\""

			[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ip6 daddr $FAKE_IP_6 jump PSW2_RULE comment \"默认\""
				add_shunt_t_rule "${SHUNT_LIST6}" "nft add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr" "counter jump PSW2_RULE" "默认"
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

filter_server_port() {
	local address=${1}
	local port=${2}
	local stream=${3}
	stream=$(echo ${3} | tr 'A-Z' 'a-z')
	local _is_tproxy
	_is_tproxy=${is_tproxy}
	[ "$stream" == "udp" ] && _is_tproxy="TPROXY"

	for _ipt in 4 6; do
		[ "$_ipt" == "4" ] && _ip_type=ip
		[ "$_ipt" == "6" ] && _ip_type=ip6
		nft "list chain $NFTABLE_NAME $nft_output_chain" 2>/dev/null | grep -q "${address}:${port}"
		if [ $? -ne 0 ]; then
			nft "insert rule $NFTABLE_NAME $nft_output_chain meta l4proto $stream $_ip_type daddr $address $stream dport $port return comment \"${address}:${port}\"" 2>/dev/null
		fi
	done
}

filter_node() {
	local node=${1}
	local stream=${2}
	if [ -n "$node" ]; then
		local address=$(config_n_get $node address)
		local port=$(config_n_get $node port)
		[ -z "$address" ] && [ -z "$port" ] && {
			return 1
		}
		filter_server_port $address $port $stream
		filter_server_port $address $port $stream
	fi
}

filter_direct_node_list() {
	[ ! -s "$TMP_PATH/direct_node_list" ] && return
	for _node_id in $(cat $TMP_PATH/direct_node_list | awk '!seen[$0]++'); do
		filter_node "$_node_id" TCP
		filter_node "$_node_id" UDP
		unset _node_id
	done
}

add_firewall_rule() {
	echolog "开始加载防火墙规则..."
	gen_nft_tables
	gen_nftset $NFTSET_LOCALLIST ipv4_addr 0 "-1"
	gen_nftset $NFTSET_LANLIST ipv4_addr 0 "-1" $(gen_lanlist)
	gen_nftset $NFTSET_VPSLIST ipv4_addr 0 0

	gen_nftset $NFTSET_LOCALLIST6 ipv6_addr 0 "-1"
	gen_nftset $NFTSET_LANLIST6 ipv6_addr 0 "-1" $(gen_lanlist_6)
	gen_nftset $NFTSET_VPSLIST6 ipv6_addr 0 0

	insert_nftset $NFTSET_LOCALLIST "-1" $(ip address show | grep -w "inet" | awk '{print $2}' | awk -F '/' '{print $1}' | sed -e "s/ /\n/g")
	insert_nftset $NFTSET_LOCALLIST6 "-1" $(ip address show | grep -w "inet6" | awk '{print $2}' | awk -F '/' '{print $1}' | sed -e "s/ /\n/g")

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
	gen_shunt_list ${NODE} SHUNT_LIST4 SHUNT_LIST6 ${WRITE_IPSET_DIRECT} ${nftset_global_whitelist} ${nftset_global_whitelist6}

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

	nft "add chain $NFTABLE_NAME PSW2_DNS"
	nft "flush chain $NFTABLE_NAME PSW2_DNS"
	if [ $(config_t_get global dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		nft "insert rule $NFTABLE_NAME dstnat ip daddr @${NFTSET_LOCALLIST} jump PSW2_DNS"
		nft "insert rule $NFTABLE_NAME dstnat ip6 daddr @${NFTSET_LOCALLIST6} jump PSW2_DNS"
	else
		nft "insert rule $NFTABLE_NAME dstnat jump PSW2_DNS"
	fi

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
		nft "add rule $NFTABLE_NAME PSW2_OUTPUT_NAT meta mark 0xff counter return"
	}

	#icmp ipv6-icmp redirect
	if [ "$accept_icmp" = "1" ]; then
		nft "add chain $NFTABLE_NAME PSW2_ICMP_REDIRECT"
		nft "flush chain $NFTABLE_NAME PSW2_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip daddr @$NFTSET_VPSLIST counter return"

		[ "$accept_icmpv6" = "1" ] && {
			nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip6 daddr @$NFTSET_LANLIST6 counter return"
			nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip6 daddr @$NFTSET_VPSLIST6 counter return"
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

	nft "add chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_LANLIST6 counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_VPSLIST6 counter return"
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

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
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

		if [ -n "$NODE" ] && ([ "$TCP_LOCALHOST_PROXY" = "1" ] || [ "$UDP_LOCALHOST_PROXY" = "1" ]); then
			[ -n "$DNS_REDIRECT_PORT" ] && {
				nft "add rule $NFTABLE_NAME nat_output ip protocol udp oif lo udp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"PSW2\""
				nft "add rule $NFTABLE_NAME nat_output ip protocol tcp oif lo tcp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"PSW2\""
				nft "add rule $NFTABLE_NAME nat_output meta l4proto udp oif lo udp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"PSW2\""
				nft "add rule $NFTABLE_NAME nat_output meta l4proto tcp oif lo tcp dport 53 counter redirect to :$DNS_REDIRECT_PORT comment \"PSW2\""
			}
		fi

		# 加载路由器自身代理 TCP
		if [ -n "$NODE" ] && [ "$TCP_LOCALHOST_PROXY" = "1" ]; then
			[ "$accept_icmp" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp ip daddr $FAKE_IP counter redirect"
				add_shunt_t_rule "${SHUNT_LIST4}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp ip daddr" "counter redirect"
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp counter redirect"
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp counter return"
			}

			[ "$accept_icmpv6" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr $FAKE_IP_6 counter redirect"
				add_shunt_t_rule "${SHUNT_LIST6}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr" "counter redirect"
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
			add_shunt_t_rule "${SHUNT_LIST4}" "nft add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr" "${nft_j}"
			nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ${nft_j}"
			[ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME nat_output ip protocol tcp counter jump PSW2_OUTPUT_NAT"
			[ -n "${is_tproxy}" ] && {
				nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp iif lo $(REDIRECT $REDIR_PORT TPROXY4) comment \"本机\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp iif lo counter return comment \"本机\""
				nft "add rule $NFTABLE_NAME mangle_output ip protocol tcp counter jump PSW2_OUTPUT_MANGLE comment \"PSW2_OUTPUT_MANGLE\""
			}

			[ "$PROXY_IPV6" == "1" ] && {
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr $FAKE_IP_6 jump PSW2_RULE"
				add_shunt_t_rule "${SHUNT_LIST6}" "nft add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr" "counter jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp iif lo $(REDIRECT $REDIR_PORT TPROXY) comment \"本机\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp iif lo counter return comment \"本机\""
			}

			[ -d "${TMP_IFACE_PATH}" ] && {
				for iface in $(ls ${TMP_IFACE_PATH}); do
					nft "insert rule $NFTABLE_NAME $nft_output_chain ip protocol tcp oif $iface counter return"
					nft "insert rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip protocol tcp oif $iface counter return"
				done
			}
		fi

		# 加载路由器自身代理 UDP
		if [ -n "$NODE" ] && [ "$UDP_LOCALHOST_PROXY" = "1" ]; then
			nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW2_RULE"
			add_shunt_t_rule "${SHUNT_LIST4}" "nft add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr" "counter jump PSW2_RULE"
			nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW2_RULE"
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp iif lo $(REDIRECT $REDIR_PORT TPROXY4) comment \"本机\""
			nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp iif lo counter return comment \"本机\""
			nft "add rule $NFTABLE_NAME mangle_output ip protocol udp counter jump PSW2_OUTPUT_MANGLE comment \"PSW2_OUTPUT_MANGLE\""

			if [ "$PROXY_IPV6_UDP" == "1" ]; then
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr $FAKE_IP_6 jump PSW2_RULE"
				add_shunt_t_rule "${SHUNT_LIST6}" "nft add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr" "counter jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp iif lo $(REDIRECT $REDIR_PORT TPROXY) comment \"本机\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp iif lo counter return comment \"本机\""
			fi

			[ -d "${TMP_IFACE_PATH}" ] && {
				for iface in $(ls ${TMP_IFACE_PATH}); do
					nft "insert rule $NFTABLE_NAME $nft_output_chain ip protocol udp oif $iface counter return"
					nft "insert rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip protocol udp oif $iface counter return"
				done
			}
		fi

		nft "add rule $NFTABLE_NAME mangle_output oif lo counter return comment \"PSW2_OUTPUT_MANGLE\""
		nft "add rule $NFTABLE_NAME mangle_output meta mark 1 counter return comment \"PSW2_OUTPUT_MANGLE\""

		nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp udp dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp udp dport 53 counter return"
	}

	#  加载ACLS
	load_acl

	filter_direct_node_list

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

	destroy_nftset $NFTSET_LOCALLIST
	destroy_nftset $NFTSET_LANLIST
	destroy_nftset $NFTSET_VPSLIST

	destroy_nftset $NFTSET_LOCALLIST6
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
	rm -f /tmp/etc/passwall2_tmp/geoip-*.json
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
filter_direct_node_list)
	filter_direct_node_list
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
