#!/bin/sh

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/iptables.sh
IPSET_LOCALLIST="passwall2_locallist"
IPSET_LANLIST="passwall2_lanlist"
IPSET_VPSLIST="passwall2_vpslist"

IPSET_LOCALLIST6="passwall2_locallist6"
IPSET_LANLIST6="passwall2_lanlist6"
IPSET_VPSLIST6="passwall2_vpslist6"

FORCE_INDEX=2

. /lib/functions/network.sh

ipt=$(command -v iptables-legacy || command -v iptables)
ip6t=$(command -v ip6tables-legacy || command -v ip6tables)

ipt_n="$ipt -t nat -w"
ipt_m="$ipt -t mangle -w"
ip6t_n="$ip6t -t nat -w"
ip6t_m="$ip6t -t mangle -w"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_nat')" ] && ip6t_n="eval #$ip6t_n"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_mangle')" ] && ip6t_m="eval #$ip6t_m"
FWI=$(uci -q get firewall.passwall2.path 2>/dev/null)
FAKE_IP="198.18.0.0/16"
FAKE_IP_6="fc00::/18"

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

dst() {
	echo "-m set $2 --match-set $1 dst"
}

comment() {
	local name=$(echo $1 | sed 's/ /_/g')
	echo "-m comment --comment '$name'"
}

destroy_ipset() {
	for i in "$@"; do
		ipset -q -F $i
		ipset -q -X $i
	done
}

insert_rule_before() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		$ipt_tmp -A $chain $rule
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		$ipt_tmp -I $chain $_index $rule
	fi
}

insert_rule_after() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | awk 'END {print}' | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		$ipt_tmp -A $chain $rule
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		$ipt_tmp -I $chain $_index $rule
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		echolog "索引列举方式不正确（iptables），终止执行！"
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local list="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$list" | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="-j REDIRECT"
	[ -n "$1" ] && {
		local s="$s --to-ports $1"
		[ "$2" == "MARK" ] && s="-j MARK --set-mark $1"
		[ "$2" == "TPROXY" ] && {
			local mark="-m mark --mark 1"
			s="${mark} -j TPROXY --tproxy-mark 0x1/0x1 --on-port $1"
		}
	}
	echo $s
}

get_redirect_ipt() {
	echo "$(REDIRECT $2 $3)"
}

get_redirect_ip6t() {
	echo "$(REDIRECT $2 $3)"
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
				local ipset_v4="passwall2_${node}_${shunt_id}"
				local ipset_v6="passwall2_${node}_${shunt_id}6"
				ipset -! create $ipset_v4 nethash maxelem 1048576
				ipset -! create $ipset_v6 nethash family inet6 maxelem 1048576
				local outbound="redirect"
				[ "$shunt_node" = "_direct" ] && outbound="direct"
				[ "$shunt_node" = "_default" ] && outbound="${default_outbound}"
				_SHUNT_LIST4="${_SHUNT_LIST4} ${ipset_v4}:${outbound}"
				_SHUNT_LIST6="${_SHUNT_LIST6} ${ipset_v6}:${outbound}"

				config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $ipset_v4 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
				config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $ipset_v6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
				[ "$(config_t_get global_rules enable_geoview)" = "1" ] && {
					local _geoip_code=$(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
					[ -n "$_geoip_code" ] && {
						if [ "$(config_n_get $node type)" = "sing-box" ]; then
							get_singbox_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $ipset_v4 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
							get_singbox_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $ipset_v6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
						else
							if type geoview &> /dev/null; then
								get_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $ipset_v4 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
								get_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $ipset_v6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
							fi
						fi
						echolog "  - [$?]解析分流规则[$shunt_id]-[geoip:${_geoip_code}]加入到 IPSET 完成"
					}
				}
			}
		done
		[ "${_write_ipset_direct}" = "1" ] && {
			_SHUNT_LIST4="${_SHUNT_LIST4} ${_set_name4}:direct"
			_SHUNT_LIST6="${_SHUNT_LIST6} ${_set_name6}:direct"
		}
		[ -n "$default_node" ] && {
			local ipset_v4="passwall2_${node}_default"
			local ipset_v6="passwall2_${node}_default6"
			ipset -! create $ipset_v4 nethash maxelem 1048576
			ipset -! create $ipset_v6 nethash family inet6 maxelem 1048576
			_SHUNT_LIST4="${_SHUNT_LIST4} ${ipset_v4}:${default_outbound}"
			_SHUNT_LIST6="${_SHUNT_LIST6} ${ipset_v6}:${default_outbound}"
		}
	}
	[ -n "${_SHUNT_LIST4}" ] && eval ${shunt_list4_var_name}=\"${_SHUNT_LIST4}\"
	[ -n "${_SHUNT_LIST6}" ] && eval ${shunt_list6_var_name}=\"${_SHUNT_LIST6}\"
}

add_shunt_t_rule() {
	local shunt_args=${1}
	local t_args=${2}
	local t_jump_args=${3}
	[ -n "${shunt_args}" ] && {
		for j in ${shunt_args}; do
			local _set_name=$(echo ${j} | awk -F ':' '{print $1}')
			local _outbound=$(echo ${j} | awk -F ':' '{print $2}')
			[ -n "${_set_name}" ] && [ -n "${_outbound}" ] && {
				local _t_arg="${t_jump_args}"
				[ "${_outbound}" = "direct" ] && _t_arg="-j RETURN"
				${t_args} $(dst ${_set_name}) ${_t_arg}
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
					local ipset_whitelist=${ipset_global_whitelist}
					local ipset_whitelist6=${ipset_global_whitelist6}
					shunt_list4=${SHUNT_LIST4}
					shunt_list6=${SHUNT_LIST6}
				else
					local ipset_whitelist="passwall2_${sid}_whitelist"
					local ipset_whitelist6="passwall2_${sid}_whitelist6"
					ipset -! create $ipset_whitelist nethash maxelem 1048576
					ipset -! create $ipset_whitelist6 nethash family inet6 maxelem 1048576

					#分流规则的IP列表(使用分流节点时导入)
					gen_shunt_list ${node} shunt_list4 shunt_list6 ${write_ipset_direct} ${ipset_whitelist} ${ipset_whitelist6}
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
					_ipt_source="-i ${device} "
					msg="源接口【${device}】，"
				fi
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "${_ipt_source}-m iprange --src-range")
					msg="${msg}IP range【${_iprange}】，"
					unset _iprange
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					msg="${msg}IPset【${_ipset}】，"
					ipset -q list ${_ipset} >/dev/null
					if [ $? -eq 0 ]; then
						_ipt_source="${_ipt_source}-m set --match-set ${_ipset} src"
						unset _ipset
					else
						echolog "  - 【$remarks】，${msg}不存在，忽略。"
						unset _ipset
						continue
					fi
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "${_ipt_source}-s")
					msg="${msg}IP【${_ip}】，"
					unset _ip
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "${_ipt_source}-m mac --mac-source")
					msg="${msg}MAC【${_mac}】，"
					unset _mac
				else
					continue
				fi
				msg="【$remarks】，${msg}"

				ipt_tmp=$ipt_n
				[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m
				
				[ "$tcp_no_redir_ports" != "disable" ] && {
					if [ "$tcp_no_redir_ports" != "1:65535" ]; then
						$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -m multiport --dport $tcp_no_redir_ports -j RETURN 2>/dev/null
						$ipt_tmp -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -m multiport --dport $tcp_no_redir_ports -j RETURN
						echolog "  - ${msg}不代理 TCP 端口[${tcp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						tcp_proxy_mode="disable"
						echolog "  - ${msg}不代理所有 TCP"
					fi
				}
				
				[ "$udp_no_redir_ports" != "disable" ] && {
					if [ "$udp_no_redir_ports" != "1:65535" ]; then
						$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -m multiport --dport $udp_no_redir_ports -j RETURN 2>/dev/null
						$ipt_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -m multiport --dport $udp_no_redir_ports -j RETURN
						echolog "  - ${msg}不代理 UDP 端口[${udp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						udp_proxy_mode="disable"
						echolog "  - ${msg}不代理所有 UDP"
					fi
				}
				
				if ([ "$tcp_proxy_mode" != "disable" ] || [ "$udp_proxy_mode" != "disable" ]) && [ -n "$dns_redirect_port" ]; then
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
				else
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j RETURN
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j RETURN 2>/dev/null
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j RETURN
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j RETURN 2>/dev/null
				fi

				[ "$tcp_proxy_mode" != "disable" ] && [ -n "$redir_port" ] && {
					msg2="${msg}使用 TCP 节点[$node_remark]"
					if [ -n "${is_tproxy}" ]; then
						msg2="${msg2}(TPROXY:${redir_port})"
						ipt_j="-j PSW2_RULE"
					else
						msg2="${msg2}(REDIRECT:${redir_port})"
						ipt_j="$(REDIRECT $redir_port)"
					fi

					[ "$accept_icmp" = "1" ] && {
						$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source} -d $FAKE_IP $(REDIRECT)
						add_shunt_t_rule "${shunt_list4}" "$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source}" "$(REDIRECT)"
						$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source} $(REDIRECT)
					}
					
					[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
						$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source} -d $FAKE_IP_6 $(REDIRECT) 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source}" "$(REDIRECT)" 2>/dev/null
						$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(REDIRECT) 2>/dev/null
					}

					$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP ${ipt_j}
					add_shunt_t_rule "${shunt_list4}" "$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport")" "${ipt_j}"
					$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") ${ipt_j}
					[ -n "${is_tproxy}" ] && $ipt_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY)

					[ "$PROXY_IPV6" == "1" ] && {
						$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP_6 -j PSW2_RULE 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport")" "${ipt_j}" 2>/dev/null
						$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") -j PSW2_RULE 2>/dev/null
						$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY) 2>/dev/null
					}
					echolog "  - ${msg2}"
				}
				$ipt_tmp -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN
				$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN 2>/dev/null

				[ "$udp_proxy_mode" != "disable" ] && [ -n "$redir_port" ] && {
					msg2="${msg}使用 UDP 节点[$node_remark](TPROXY:${redir_port})"

					$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP -j PSW2_RULE
					add_shunt_t_rule "${shunt_list4}" "$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport")" "-j PSW2_RULE"
					$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") -j PSW2_RULE
					$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $redir_port TPROXY)

					[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
						$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP_6 -j PSW2_RULE 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport")" "-j PSW2_RULE" 2>/dev/null
						$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") -j PSW2_RULE 2>/dev/null
						$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $redir_port TPROXY) 2>/dev/null
					}
					echolog "  - ${msg2}"
				}
				$ipt_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -j RETURN
				$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -j RETURN 2>/dev/null
				unset ipt_tmp ipt_j _ipt_source msg msg2
			done
			unset enabled sid remarks sources tcp_no_redir_ports udp_no_redir_ports tcp_redir_ports udp_redir_ports node interface
			unset node_remark _acl_list
		done
	}
	
	[ "$ENABLED_DEFAULT_ACL" == 1 ] && [ "$CLIENT_PROXY" == 1 ] && {
		#  加载默认代理模式
		msg="【默认】，"
		local ipt_tmp=$ipt_n
		[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m

		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			$ip6t_m -A PSW2 $(comment "默认") -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			$ipt_tmp -A PSW2 $(comment "默认") -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			if [ "$TCP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				TCP_PROXY_MODE="disable"
				echolog "  - ${msg}不代理所有 TCP 端口"
			fi
		}

		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			$ip6t_m -A PSW2 $(comment "默认") -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			$ipt_m -A PSW2 $(comment "默认") -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			if [ "$UDP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				UDP_PROXY_MODE="disable"
				echolog "  - ${msg}不代理所有 UDP 端口"
			fi
		}

		if ([ "$TCP_PROXY_MODE" != "disable" ] || [ "$UDP_PROXY_MODE" != "disable" ]) && [ -n "$NODE" ]; then
			[ -n "$DNS_REDIRECT_PORT" ] && {
				$ipt_n -A PSW2_DNS $(comment "默认") -p udp --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT
				$ip6t_n -A PSW2_DNS $(comment "默认") -p udp --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT 2>/dev/null
				$ipt_n -A PSW2_DNS $(comment "默认") -p tcp --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT
				$ip6t_n -A PSW2_DNS $(comment "默认") -p tcp --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT 2>/dev/null
			}
		fi

		if [ "$TCP_PROXY_MODE" != "disable" ] && [ -n "$NODE" ]; then
			msg2="${msg}使用 TCP 节点[$(config_n_get $NODE remarks)]"
			if [ -n "${is_tproxy}" ]; then
				msg2="${msg2}(TPROXY:${REDIR_PORT})"
				ipt_j="-j PSW2_RULE"
			else
				msg2="${msg2}(REDIRECT:${REDIR_PORT})"
				ipt_j="$(REDIRECT $REDIR_PORT)"
			fi

			[ "$accept_icmp" = "1" ] && {
				$ipt_n -A PSW2 $(comment "默认") -p icmp -d $FAKE_IP $(REDIRECT)
				add_shunt_t_rule "${SHUNT_LIST4}" "$ipt_n -A PSW2 $(comment "默认") -p icmp" "$(REDIRECT)"
				$ipt_n -A PSW2 $(comment "默认") -p icmp $(REDIRECT)
			}
			
			[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
				$ip6t_n -A PSW2 $(comment "默认") -p ipv6-icmp -d $FAKE_IP_6 $(REDIRECT)
				add_shunt_t_rule "${SHUNT_LIST6}" "$ip6t_n -A PSW2 $(comment "默认") -p ipv6-icmp" "$(REDIRECT)"
				$ip6t_n -A PSW2 $(comment "默认") -p ipv6-icmp $(REDIRECT)
			}

			$ipt_tmp -A PSW2 $(comment "默认") -p tcp -d $FAKE_IP ${ipt_j}
			add_shunt_t_rule "${SHUNT_LIST4}" "$ipt_tmp -A PSW2 $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport")" "${ipt_j}"
			$ipt_tmp -A PSW2 $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") ${ipt_j}
			[ -n "${is_tproxy}" ] && $ipt_m -A PSW2 $(comment "默认") -p tcp $(REDIRECT $REDIR_PORT TPROXY)

			[ "$PROXY_IPV6" == "1" ] && {
				$ip6t_m -A PSW2 $(comment "默认") -p tcp -d $FAKE_IP_6 -j PSW2_RULE
				add_shunt_t_rule "${SHUNT_LIST6}" "$ip6t_m -A PSW2 $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport")" "-j PSW2_RULE"
				$ip6t_m -A PSW2 $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") -j PSW2_RULE
				$ip6t_m -A PSW2 $(comment "默认") -p tcp $(REDIRECT $REDIR_PORT TPROXY)
			}

			echolog "${msg2}"
		fi

		if [ "$UDP_PROXY_MODE" != "disable" ] && [ -n "$NODE" ]; then
			msg2="${msg}使用 UDP 节点[$(config_n_get $NODE remarks)](TPROXY:${REDIR_PORT})"

			$ipt_m -A PSW2 $(comment "默认") -p udp -d $FAKE_IP -j PSW2_RULE
			add_shunt_t_rule "${SHUNT_LIST4}" "$ipt_m -A PSW2 $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport")" "-j PSW2_RULE"
			$ipt_m -A PSW2 $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") -j PSW2_RULE
			$ipt_m -A PSW2 $(comment "默认") -p udp $(REDIRECT $REDIR_PORT TPROXY)

			if [ "$PROXY_IPV6_UDP" == "1" ]; then
				$ip6t_m -A PSW2 $(comment "默认") -p udp -d $FAKE_IP_6 -j PSW2_RULE
				add_shunt_t_rule "${SHUNT_LIST6}" "$ip6t_m -A PSW2 $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport")" "-j PSW2_RULE"
				$ip6t_m -A PSW2 $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") -j PSW2_RULE
				$ip6t_m -A PSW2 $(comment "默认") -p udp $(REDIRECT $REDIR_PORT TPROXY)
			fi

			echolog "${msg2}"
		fi
	}
}

filter_haproxy() {
	for item in $(uci show $CONFIG | grep ".lbss=" | cut -d "'" -f 2); do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		[ -n "$ip" ] && ipset -q add $IPSET_VPSLIST $ip
	done
	echolog "加入负载均衡的节点到ipset[$IPSET_VPSLIST]直连完成"
}

filter_vpsip() {
	uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -v "^127\.0\.0\.1$" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPSLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	echolog "  - [$?]加入所有IPv4节点到ipset[$IPSET_VPSLIST]直连完成"
	uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPSLIST6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	echolog "  - [$?]加入所有IPv6节点到ipset[$IPSET_VPSLIST6]直连完成"
}

filter_server_port() {
	local address=${1}
	local port=${2}
	local stream=${3}
	stream=$(echo ${3} | tr 'A-Z' 'a-z')
	local _is_tproxy ipt_tmp
	ipt_tmp=$ipt_n
	_is_tproxy=${is_tproxy}
	[ "$stream" == "udp" ] && _is_tproxy="TPROXY"
	[ -n "${_is_tproxy}" ] && ipt_tmp=$ipt_m

	for _ipt in 4 6; do
		[ "$_ipt" == "4" ] && _ipt=$ipt_tmp
		[ "$_ipt" == "6" ] && _ipt=$ip6t_m
		$_ipt -n -L PSW2_OUTPUT | grep -q "${address}:${port}"
		if [ $? -ne 0 ]; then
			$_ipt -I PSW2_OUTPUT $(comment "${address}:${port}") -p $stream -d $address --dport $port -j RETURN 2>/dev/null
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
	ipset -! create $IPSET_LOCALLIST nethash maxelem 1048576
	ipset -! create $IPSET_LANLIST nethash maxelem 1048576
	ipset -! create $IPSET_VPSLIST nethash maxelem 1048576

	ipset -! create $IPSET_LOCALLIST6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_LANLIST6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_VPSLIST6 nethash family inet6 maxelem 1048576
	
	ipset -! -R <<-EOF
		$(ip address show | grep -w "inet" | awk '{print $2}' | awk -F '/' '{print $1}' | sed -e "s/^/add $IPSET_LOCALLIST /")
	EOF
	ipset -! -R <<-EOF
		$(ip address show | grep -w "inet6" | awk '{print $2}' | awk -F '/' '{print $1}' | sed -e "s/^/add $IPSET_LOCALLIST6 /")
	EOF

	ipset -! -R <<-EOF
		$(gen_lanlist | sed -e "s/^/add $IPSET_LANLIST /")
	EOF

	ipset -! -R <<-EOF
		$(gen_lanlist_6 | sed -e "s/^/add $IPSET_LANLIST6 /")
	EOF

	# 忽略特殊IP段
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#echolog "本机IPv4网段互访直连：${lan_ip}"
		#echolog "本机IPv6网段互访直连：${lan_ip6}"

		[ -n "$lan_ip" ] && ipset -! -R <<-EOF
			$(echo $lan_ip | sed -e "s/ /\n/g" | sed -e "s/^/add $IPSET_LANLIST /")
		EOF

		[ -n "$lan_ip6" ] && ipset -! -R <<-EOF
			$(echo $lan_ip6 | sed -e "s/ /\n/g" | sed -e "s/^/add $IPSET_LANLIST6 /")
		EOF
	}

	[ -n "$ISP_DNS" ] && {
		#echolog "处理 ISP DNS 例外..."
		for ispip in $ISP_DNS; do
			ipset -! add $IPSET_LANLIST $ispip
			echolog "  - [$?]追加ISP IPv4 DNS到白名单：${ispip}"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		#echolog "处理 ISP IPv6 DNS 例外..."
		for ispip6 in $ISP_DNS6; do
			ipset -! add $IPSET_LANLIST6 $ispip6
			echolog "  - [$?]追加ISP IPv6 DNS到白名单：${ispip6}"
		done
	}
	
	local ipset_global_whitelist="passwall2_global_whitelist"
	local ipset_global_whitelist6="passwall2_global_whitelist6"
	ipset -! create $ipset_global_whitelist nethash maxelem 1048576 timeout 259200
	ipset -! create $ipset_global_whitelist6 nethash family inet6 maxelem 1048576 timeout 259200

	#分流规则的IP列表(使用分流节点时导入)
	gen_shunt_list ${NODE} SHUNT_LIST4 SHUNT_LIST6 ${WRITE_IPSET_DIRECT} ${ipset_global_whitelist} ${ipset_global_whitelist6}

	#  过滤所有节点IP
	filter_vpsip > /dev/null 2>&1 &
	filter_haproxy > /dev/null 2>&1 &

	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	local tcp_proxy_way=$(config_t_get global_forwarding tcp_proxy_way redirect)
	if [ "$tcp_proxy_way" = "redirect" ]; then
		unset is_tproxy
	elif [ "$tcp_proxy_way" = "tproxy" ]; then
		is_tproxy="TPROXY"
	fi

	$ipt_n -N PSW2
	$ipt_n -A PSW2 $(dst $IPSET_LANLIST) -j RETURN
	$ipt_n -A PSW2 $(dst $IPSET_VPSLIST) -j RETURN

	WAN_IP=$(get_wan_ip)
	[ ! -z "${WAN_IP}" ] && $ipt_n -A PSW2 $(comment "WAN_IP_RETURN") -d "${WAN_IP}" -j RETURN
	
	[ "$accept_icmp" = "1" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p icmp -j PSW2"
	[ -z "${is_tproxy}" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p tcp -j PSW2"

	$ipt_n -N PSW2_OUTPUT
	$ipt_n -A PSW2_OUTPUT $(dst $IPSET_LANLIST) -j RETURN
	$ipt_n -A PSW2_OUTPUT $(dst $IPSET_VPSLIST) -j RETURN
	$ipt_n -A PSW2_OUTPUT -m mark --mark 0xff -j RETURN

	$ipt_n -N PSW2_DNS
	if [ $(config_t_get global dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		$ipt_n -I PREROUTING $(dst $IPSET_LOCALLIST) -j PSW2_DNS
	else
		$ipt_n -I PREROUTING -j PSW2_DNS
	fi

	$ipt_m -N PSW2_DIVERT
	$ipt_m -A PSW2_DIVERT -j MARK --set-mark 1
	$ipt_m -A PSW2_DIVERT -j ACCEPT
	
	$ipt_m -N PSW2_RULE
	$ipt_m -A PSW2_RULE -j CONNMARK --restore-mark
	$ipt_m -A PSW2_RULE -m mark --mark 0x1 -j RETURN
	$ipt_m -A PSW2_RULE -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j MARK --set-xmark 1
	$ipt_m -A PSW2_RULE -p udp -m conntrack --ctstate NEW -j MARK --set-xmark 1
	$ipt_m -A PSW2_RULE -j CONNMARK --save-mark

	$ipt_m -N PSW2
	$ipt_m -A PSW2 $(dst $IPSET_LANLIST) -j RETURN
	$ipt_m -A PSW2 $(dst $IPSET_VPSLIST) -j RETURN
	
	[ ! -z "${WAN_IP}" ] && $ipt_m -A PSW2 $(comment "WAN_IP_RETURN") -d "${WAN_IP}" -j RETURN
	unset WAN_IP

	insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "-j PSW2"
	insert_rule_before "$ipt_m" "PREROUTING" "PSW2" "-p tcp -m socket -j PSW2_DIVERT"

	$ipt_m -N PSW2_OUTPUT
	$ipt_m -A PSW2_OUTPUT $(dst $IPSET_LANLIST) -j RETURN
	$ipt_m -A PSW2_OUTPUT $(dst $IPSET_VPSLIST) -j RETURN
	[ -n "$AUTO_DNS" ] && {
		for auto_dns in $(echo $AUTO_DNS | tr ',' ' '); do
			local dns_address=$(echo $auto_dns | awk -F '#' '{print $1}')
			local dns_port=$(echo $auto_dns | awk -F '#' '{print $2}')
			$ipt_m -A PSW2_OUTPUT -p udp -d ${dns_address} --dport ${dns_port:-53} -j RETURN
			echolog "  - [$?]追加直连DNS到iptables：${dns_address}:${dns_port:-53}"
		done
	}
	$ipt_m -A PSW2_OUTPUT -m mark --mark 0xff -j RETURN

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	[ "$accept_icmpv6" = "1" ] && {
		$ip6t_n -N PSW2
		$ip6t_n -A PSW2 $(dst $IPSET_LANLIST6) -j RETURN
		$ip6t_n -A PSW2 $(dst $IPSET_VPSLIST6) -j RETURN
		$ip6t_n -A PREROUTING -p ipv6-icmp -j PSW2

		$ip6t_n -N PSW2_OUTPUT
		$ip6t_n -A PSW2_OUTPUT $(dst $IPSET_LANLIST6) -j RETURN
		$ip6t_n -A PSW2_OUTPUT $(dst $IPSET_VPSLIST6) -j RETURN
		$ip6t_n -A PSW2_OUTPUT -m mark --mark 0xff -j RETURN
	}
	
	$ip6t_n -N PSW2_DNS
	if [ $(config_t_get global dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		$ip6t_n -I PREROUTING $(dst $IPSET_LOCALLIST6) -j PSW2_DNS
	else
		$ip6t_n -I PREROUTING -j PSW2_DNS
	fi

	$ip6t_m -N PSW2_DIVERT
	$ip6t_m -A PSW2_DIVERT -j MARK --set-mark 1
	$ip6t_m -A PSW2_DIVERT -j ACCEPT
	
	$ip6t_m -N PSW2_RULE
	$ip6t_m -A PSW2_RULE -j CONNMARK --restore-mark
	$ip6t_m -A PSW2_RULE -m mark --mark 0x1 -j RETURN
	$ip6t_m -A PSW2_RULE -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j MARK --set-xmark 1
	$ip6t_m -A PSW2_RULE -p udp -m conntrack --ctstate NEW -j MARK --set-xmark 1
	$ip6t_m -A PSW2_RULE -j CONNMARK --save-mark

	$ip6t_m -N PSW2
	$ip6t_m -A PSW2 $(dst $IPSET_LANLIST6) -j RETURN
	$ip6t_m -A PSW2 $(dst $IPSET_VPSLIST6) -j RETURN
	
	WAN6_IP=$(get_wan6_ip)
	[ ! -z "${WAN6_IP}" ] && $ip6t_m -A PSW2 $(comment "WAN6_IP_RETURN") -d ${WAN6_IP} -j RETURN
	unset WAN6_IP

	insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "-j PSW2"
	insert_rule_before "$ip6t_m" "PREROUTING" "PSW2" "-p tcp -m socket -j PSW2_DIVERT"

	$ip6t_m -N PSW2_OUTPUT
	$ip6t_m -A PSW2_OUTPUT -m mark --mark 0xff -j RETURN
	$ip6t_m -A PSW2_OUTPUT $(dst $IPSET_LANLIST6) -j RETURN
	$ip6t_m -A PSW2_OUTPUT $(dst $IPSET_VPSLIST6) -j RETURN

	ip -6 rule add fwmark 1 table 100
	ip -6 route add local ::/0 dev lo table 100

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
		local ipt_tmp=$ipt_n
		[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m
		
		TCP_LOCALHOST_PROXY=$LOCALHOST_PROXY
		UDP_LOCALHOST_PROXY=$LOCALHOST_PROXY
		
		msg="【路由器本机】，"
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_tmp -A PSW2_OUTPUT -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW2_OUTPUT -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			if [ "$TCP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				unset TCP_LOCALHOST_PROXY
				echolog "  - ${msg}不代理所有 TCP"
			fi
		}
		
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_m -A PSW2_OUTPUT -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW2_OUTPUT -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			if [ "$UDP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				unset UDP_LOCALHOST_PROXY
				echolog "  - ${msg}不代理所有 UDP"
			fi
		}
		
		if [ -n "$NODE" ] && ([ "$TCP_LOCALHOST_PROXY" = "1" ] || [ "$UDP_LOCALHOST_PROXY" = "1" ]); then
			[ -n "$DNS_REDIRECT_PORT" ] && {
				$ipt_n -A OUTPUT $(comment "PSW2") -p udp -o lo --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT
				$ip6t_n -A OUTPUT $(comment "PSW2") -p udp -o lo --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT 2>/dev/null
				$ipt_n -A OUTPUT $(comment "PSW2") -p tcp -o lo --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT
				$ip6t_n -A OUTPUT $(comment "PSW2") -p tcp -o lo --dport 53 -j REDIRECT --to-ports $DNS_REDIRECT_PORT 2>/dev/null
			}
		fi
	
		# 加载路由器自身代理 TCP
		if [ -n "$NODE" ] && [ "$TCP_LOCALHOST_PROXY" = "1" ]; then
			[ "$accept_icmp" = "1" ] && {
				$ipt_n -A OUTPUT -p icmp -j PSW2_OUTPUT
				$ipt_n -A PSW2_OUTPUT -p icmp -d $FAKE_IP $(REDIRECT)
				add_shunt_t_rule "${SHUNT_LIST4}" "$ipt_n -A PSW2_OUTPUT -p icmp" "$(REDIRECT)"
				$ipt_n -A PSW2_OUTPUT -p icmp $(REDIRECT)
			}

			[ "$accept_icmpv6" = "1" ] && {
				$ip6t_n -A OUTPUT -p ipv6-icmp -j PSW2_OUTPUT
				$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp -d $FAKE_IP_6 $(REDIRECT)
				add_shunt_t_rule "${SHUNT_LIST6}" "$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp" "$(REDIRECT)"
				$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp $(REDIRECT)
			}

			if [ -n "${is_tproxy}" ]; then
				ipt_j="-j PSW2_RULE"
			else
				ipt_j="$(REDIRECT $REDIR_PORT)"
			fi

			$ipt_tmp -A PSW2_OUTPUT -p tcp -d $FAKE_IP ${ipt_j}
			add_shunt_t_rule "${SHUNT_LIST4}" "$ipt_tmp -A PSW2_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport")" "${ipt_j}"
			$ipt_tmp -A PSW2_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") ${ipt_j}
			[ -z "${is_tproxy}" ] && $ipt_n -A OUTPUT -p tcp -j PSW2_OUTPUT
			[ -n "${is_tproxy}" ] && {
				$ipt_m -A PSW2 $(comment "本机") -p tcp -i lo $(REDIRECT $REDIR_PORT TPROXY)
				$ipt_m -A PSW2 $(comment "本机") -p tcp -i lo -j RETURN
				insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -p tcp -j PSW2_OUTPUT"
			}

			if [ "$PROXY_IPV6" == "1" ]; then
				$ip6t_m -A PSW2_OUTPUT -p tcp -d $FAKE_IP_6 -j PSW2_RULE
				add_shunt_t_rule "${SHUNT_LIST6}" "$ip6t_m -A PSW2_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport")" "-j PSW2_RULE"
				$ip6t_m -A PSW2_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") -j PSW2_RULE
				$ip6t_m -A PSW2 $(comment "本机") -p tcp -i lo $(REDIRECT $REDIR_PORT TPROXY)
				$ip6t_m -A PSW2 $(comment "本机") -p tcp -i lo -j RETURN
				insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -p tcp -j PSW2_OUTPUT"
			fi

			[ -d "${TMP_IFACE_PATH}" ] && {
				for iface in $(ls ${TMP_IFACE_PATH}); do
					$ipt_n -I PSW2_OUTPUT -o $iface -p tcp -j RETURN
					$ipt_m -I PSW2_OUTPUT -o $iface -p tcp -j RETURN
				done
			}
		fi

		# 加载路由器自身代理 UDP
		if [ -n "$NODE" ] && [ "$UDP_LOCALHOST_PROXY" = "1" ]; then
			$ipt_m -A PSW2_OUTPUT -p udp -d $FAKE_IP -j PSW2_RULE
			add_shunt_t_rule "${SHUNT_LIST4}" "$ipt_m -A PSW2_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport")" "-j PSW2_RULE"
			$ipt_m -A PSW2_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") -j PSW2_RULE
			$ipt_m -A PSW2 $(comment "本机") -p udp -i lo $(REDIRECT $REDIR_PORT TPROXY)
			$ipt_m -A PSW2 $(comment "本机") -p udp -i lo -j RETURN
			insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -p udp -j PSW2_OUTPUT"

			if [ "$PROXY_IPV6_UDP" == "1" ]; then
				$ip6t_m -A PSW2_OUTPUT -p udp -d $FAKE_IP_6 -j PSW2_RULE
				add_shunt_t_rule "${SHUNT_LIST6}" "$ip6t_m -A PSW2_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport")" "-j PSW2_RULE"
				$ip6t_m -A PSW2_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") -j PSW2_RULE
				$ip6t_m -A PSW2 $(comment "本机") -p udp -i lo $(REDIRECT $REDIR_PORT TPROXY)
				$ip6t_m -A PSW2 $(comment "本机") -p udp -i lo -j RETURN
				insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -p udp -j PSW2_OUTPUT"
			fi

			[ -d "${TMP_IFACE_PATH}" ] && {
				for iface in $(ls ${TMP_IFACE_PATH}); do
					$ipt_n -I PSW2_OUTPUT -o $iface -p udp -j RETURN
					$ipt_m -I PSW2_OUTPUT -o $iface -p udp -j RETURN
				done
			}
		fi
		
		$ipt_m -I OUTPUT $(comment "mangle-OUTPUT-PSW2") -o lo -j RETURN
		insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -m mark --mark 1 -j RETURN"
		
		$ip6t_m -I OUTPUT $(comment "mangle-OUTPUT-PSW2") -o lo -j RETURN
		insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -m mark --mark 1 -j RETURN"

		$ipt_m -A PSW2 -p udp --dport 53 -j RETURN
		$ip6t_m -A PSW2 -p udp --dport 53 -j RETURN
	}

	#  加载ACLS
	load_acl

	filter_direct_node_list

	echolog "防火墙规则加载完成！"
}

del_firewall_rule() {
	for ipt in "$ipt_n" "$ipt_m" "$ip6t_n" "$ip6t_m"; do
		for chain in "PREROUTING" "OUTPUT"; do
			for i in $(seq 1 $($ipt -nL $chain | grep -c PSW2)); do
				local index=$($ipt --line-number -nL $chain | grep PSW2 | head -1 | awk '{print $1}')
				$ipt -D $chain $index 2>/dev/null
			done
		done
		for chain in "PSW2" "PSW2_OUTPUT" "PSW2_DIVERT" "PSW2_DNS" "PSW2_RULE"; do
			$ipt -F $chain 2>/dev/null
			$ipt -X $chain 2>/dev/null
		done
	done

	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ip -6 rule del fwmark 1 table 100 2>/dev/null
	ip -6 route del local ::/0 dev lo table 100 2>/dev/null

	$DIR/app.sh echolog "删除iptables防火墙规则完成。"
}

flush_ipset() {
	$DIR/app.sh echolog "清空 IPSET。"
	for _name in $(ipset list | grep "Name: " | grep "passwall2_" | awk '{print $2}'); do
		destroy_ipset ${_name}
	done
}

flush_ipset_reload() {
	del_firewall_rule
	flush_ipset
	rm -rf /tmp/singbox_passwall2_*
	rm -f /tmp/etc/passwall2_tmp/geoip-*.json
	/etc/init.d/passwall2 reload
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	extract_rules() {
		local _ipt="${ipt}"
		[ "$1" == "6" ] && _ipt="${ip6t}"
		[ -z "${_ipt}" ] && return

		echo "*$2"
		${_ipt}-save -t $2 | grep "PSW2" | grep -v "\-j PSW2$" | grep -v "socket \-j PSW2_DIVERT$" | sed -e "s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/"
		echo 'COMMIT'
	}
	local __ipt=""
	[ -n "${ipt}" ] && {
		__ipt=$(cat <<- EOF
			$ipt-save -c | grep -v "PSW2" | $ipt-restore -c
			$ipt-restore -n <<-EOT
			$(extract_rules 4 nat)
			$(extract_rules 4 mangle)
			EOT

			[ "$accept_icmp" = "1" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p icmp -j PSW2")
			[ -z "${is_tproxy}" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p tcp -j PSW2")

			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "-j PSW2")
			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "PSW2" "-p tcp -m socket -j PSW2_DIVERT")

			WAN_IP=\$(${MY_PATH} get_wan_ip)

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ipt_n" PSW2 WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				[ ! -z "\${WAN_IP}" ] && $ipt_n -R PSW2 \$PR_INDEX $(comment "WAN_IP_RETURN") -d "\${WAN_IP}" -j RETURN
			fi

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ipt_m" PSW2 WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				[ ! -z "\${WAN_IP}" ] && $ipt_m -R PSW2 \$PR_INDEX $(comment "WAN_IP_RETURN") -d "\${WAN_IP}" -j RETURN
			fi
		EOF
		)
	}
	local __ip6t=""
	[ -n "${ip6t}" ] && {
		__ip6t=$(cat <<- EOF
			$ip6t-save -c | grep -v "PSW2" | $ip6t-restore -c
			$ip6t-restore -n <<-EOT
			$(extract_rules 6 nat)
			$(extract_rules 6 mangle)
			EOT

			[ "$accept_icmpv6" = "1" ] && $ip6t_n -A PREROUTING -p ipv6-icmp -j PSW2

			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "-j PSW2")
			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "PSW2" "-p tcp -m socket -j PSW2_DIVERT")

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ip6t_m" PSW2 WAN6_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN6_IP=\$(${MY_PATH} get_wan6_ip)
				[ ! -z "\${WAN6_IP}" ] && $ip6t_m -R PSW2 \$PR_INDEX $(comment "WAN6_IP_RETURN") -d "\${WAN6_IP}" -j RETURN
			fi
		EOF
		)
	}
	cat <<-EOF >> $FWI
		${__ipt}
		
		${__ip6t}
	EOF
	return 0
}

get_ipt_bin() {
	echo $ipt
}

get_ip6t_bin() {
	echo $ip6t
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
flush_ipset)
	flush_ipset
	;;
flush_ipset_reload)
	flush_ipset_reload
	;;
get_ipt_bin)
	get_ipt_bin
	;;
get_ip6t_bin)
	get_ip6t_bin
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
