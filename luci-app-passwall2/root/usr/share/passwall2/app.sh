#!/bin/sh
# Copyright (C) 2022-2025 xiaorouji

. $IPKG_INSTROOT/lib/functions.sh
. $IPKG_INSTROOT/lib/functions/service.sh

CONFIG=passwall2
TMP_PATH=/tmp/etc/$CONFIG
TMP_BIN_PATH=$TMP_PATH/bin
TMP_SCRIPT_FUNC_PATH=$TMP_PATH/script_func
TMP_ROUTE_PATH=$TMP_PATH/route
TMP_ACL_PATH=$TMP_PATH/acl
TMP_IFACE_PATH=$TMP_PATH/iface
TMP_PATH2=/tmp/etc/${CONFIG}_tmp
GLOBAL_ACL_PATH=${TMP_ACL_PATH}/default
LOG_FILE=/tmp/log/$CONFIG.log
APP_PATH=/usr/share/$CONFIG
RULES_PATH=/usr/share/${CONFIG}/rules
LUA_UTIL_PATH=/usr/lib/lua/luci/passwall2
UTIL_SINGBOX=$LUA_UTIL_PATH/util_sing-box.lua
UTIL_SS=$LUA_UTIL_PATH/util_shadowsocks.lua
UTIL_XRAY=$LUA_UTIL_PATH/util_xray.lua
UTIL_NAIVE=$LUA_UTIL_PATH/util_naiveproxy.lua
UTIL_HYSTERIA2=$LUA_UTIL_PATH/util_hysteria2.lua
UTIL_TUIC=$LUA_UTIL_PATH/util_tuic.lua

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$LOG_FILE
}

config_get_type() {
	local ret=$(uci -q get "${CONFIG}.${1}" 2>/dev/null)
	echo "${ret:=$2}"
}

config_n_get() {
	local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}

config_t_get() {
	local index=${4:-0}
	local ret=$(uci -q get "${CONFIG}.@${1}[${index}].${2}" 2>/dev/null)
	echo "${ret:=${3}}"
}

config_t_set() {
	local index=${4:-0}
	local ret=$(uci -q set "${CONFIG}.@${1}[${index}].${2}=${3}" 2>/dev/null)
}

get_enabled_anonymous_secs() {
	uci -q show "${CONFIG}" | grep "${1}\[.*\.enabled='1'" | cut -d '.' -sf2
}

get_host_ip() {
	local host=$2
	local count=$3
	[ -z "$count" ] && count=3
	local isip=""
	local ip=$host
	if [ "$1" == "ipv6" ]; then
		isip=$(echo $host | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		if [ -n "$isip" ]; then
			isip=$(echo $host | cut -d '[' -f2 | cut -d ']' -f1)
		else
			isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
		fi
	else
		isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
	fi
	[ -z "$isip" ] && {
		local t=4
		[ "$1" == "ipv6" ] && t=6
		local vpsrip=$(resolveip -$t -t $count $host | awk 'NR==1{print}')
		ip=$vpsrip
	}
	echo $ip
}

get_node_host_ip() {
	local ip
	local address=$(config_n_get $1 address)
	[ -n "$address" ] && {
		local use_ipv6=$(config_n_get $1 use_ipv6)
		local network_type="ipv4"
		[ "$use_ipv6" == "1" ] && network_type="ipv6"
		ip=$(get_host_ip $network_type $address)
	}
	echo $ip
}

get_ip_port_from() {
	local __host=${1}; shift 1
	local __ipv=${1}; shift 1
	local __portv=${1}; shift 1
	local __ucipriority=${1}; shift 1

	local val1 val2
	if [ -n "${__ucipriority}" ]; then
		val2=$(config_n_get ${__host} port $(echo $__host | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p'))
		val1=$(config_n_get ${__host} address "${__host%%${val2:+[:#]${val2}*}}")
	else
		val2=$(echo $__host | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p')
		val1="${__host%%${val2:+[:#]${val2}*}}"
	fi
	eval "${__ipv}=\"$val1\"; ${__portv}=\"$val2\""
}

host_from_url(){
	local f=${1}

	## Remove protocol part of url  ##
	f="${f##http://}"
	f="${f##https://}"
	f="${f##ftp://}"
	f="${f##sftp://}"

	## Remove username and/or username:password part of URL  ##
	f="${f##*:*@}"
	f="${f##*@}"

	## Remove rest of urls ##
	f="${f%%/*}"
	echo "${f%%:*}"
}

hosts_foreach() {
	local __hosts
	eval "__hosts=\$${1}"; shift 1
	local __func=${1}; shift 1
	local __default_port=${1}; shift 1
	local __ret=1

	[ -z "${__hosts}" ] && return 0
	local __ip __port
	for __host in $(echo $__hosts | sed 's/[ ,]/\n/g'); do
		get_ip_port_from "$__host" "__ip" "__port"
		eval "$__func \"${__host}\" \"\${__ip}\" \"\${__port:-${__default_port}}\" \"$@\""
		__ret=$?
		[ ${__ret} -ge ${ERROR_NO_CATCH:-1} ] && return ${__ret}
	done
}

check_host() {
	local f=${1}
	a=$(echo $f | grep "\/")
	[ -n "$a" ] && return 1
	# 判断是否包含汉字~
	local tmp=$(echo -n $f | awk '{print gensub(/[!-~]/,"","g",$0)}')
	[ -n "$tmp" ] && return 1
	return 0
}

get_first_dns() {
	local __hosts_val=${1}; shift 1
	__first() {
		[ -z "${2}" ] && return 0
		echo "${2}#${3}"
		return 1
	}
	eval "hosts_foreach \"${__hosts_val}\" __first \"$@\""
}

get_last_dns() {
	local __hosts_val=${1}; shift 1
	local __first __last
	__every() {
		[ -z "${2}" ] && return 0
		__last="${2}#${3}"
		__first=${__first:-${__last}}
	}
	eval "hosts_foreach \"${__hosts_val}\" __every \"$@\""
	[ "${__first}" ==  "${__last}" ] || echo "${__last}"
}

check_port_exists() {
	local port=$1
	local protocol=$2
	[ -n "$protocol" ] || protocol="tcp,udp"
	local result=
	if [ "$protocol" = "tcp" ]; then
		result=$(netstat -tln | grep -c ":$port ")
	elif [ "$protocol" = "udp" ]; then
		result=$(netstat -uln | grep -c ":$port ")
	elif [ "$protocol" = "tcp,udp" ]; then
		result=$(netstat -tuln | grep -c ":$port ")
	fi
	echo "${result}"
}

get_new_port() {
	local port=$1
	[ "$port" == "auto" ] && port=2082
	local protocol=$(echo $2 | tr 'A-Z' 'a-z')
	local result=$(check_port_exists $port $protocol)
	if [ "$result" != 0 ]; then
		local temp=
		if [ "$port" -lt 65535 ]; then
			temp=$(expr $port + 1)
		elif [ "$port" -gt 1 ]; then
			temp=$(expr $port - 1)
		fi
		get_new_port $temp $protocol
	else
		echo $port
	fi
}

check_depends() {
	local depends
	local tables=${1}
	local file_path="/usr/lib/opkg/info"
	local file_ext=".control"
	[ -d "/lib/apk/packages" ] && file_path="/lib/apk/packages" && file_ext=".list"
	if [ "$tables" == "iptables" ]; then
		for depends in "iptables-mod-tproxy" "iptables-mod-socket" "iptables-mod-iprange" "iptables-mod-conntrack-extra" "kmod-ipt-nat"; do
			[ -s "${file_path}/${depends}${file_ext}" ] || echolog "$tables透明代理基础依赖 $depends 未安装..."
		done
	else
		for depends in "kmod-nft-socket" "kmod-nft-tproxy" "kmod-nft-nat"; do
			[ -s "${file_path}/${depends}${file_ext}" ] || echolog "$tables透明代理基础依赖 $depends 未安装..."
		done
	fi
}

first_type() {
	local path_name=${1}
	type -t -p "/bin/${path_name}" -p "${TMP_BIN_PATH}/${path_name}" -p "${path_name}" "$@" | head -n1
}

eval_set_val() {
	for i in $@; do
		for j in $i; do
			eval $j
		done
	done
}

eval_unset_val() {
	for i in $@; do
		for j in $i; do
			eval unset j
		done
	done
}

ln_run() {
	local file_func=${1}
	local ln_name=${2}
	local output=${3}

	shift 3;
	if [  "${file_func%%/*}" != "${file_func}" ]; then
		[ ! -L "${file_func}" ] && {
			ln -s "${file_func}" "${TMP_BIN_PATH}/${ln_name}" >/dev/null 2>&1
			file_func="${TMP_BIN_PATH}/${ln_name}"
		}
		[ -x "${file_func}" ] || echolog "  - $(readlink ${file_func}) 没有执行权限，无法启动：${file_func} $*"
	fi
	#echo "${file_func} $*" >&2
	[ -n "${file_func}" ] || echolog "  - 找不到 ${ln_name}，无法启动..."
	${file_func:-echolog "  - ${ln_name}"} "$@" >${output} 2>&1 &
	process_count=$(ls $TMP_SCRIPT_FUNC_PATH | grep -v "^_" | wc -l)
	process_count=$((process_count + 1))
	echo "${file_func:-echolog "  - ${ln_name}"} $@ >${output}" > $TMP_SCRIPT_FUNC_PATH/$process_count
}

lua_api() {
	local func=${1}
	[ -z "${func}" ] && {
		echo ""
		return
	}
	echo $(lua -e "local api = require 'luci.passwall2.api' print(api.${func})")
}

get_geoip() {
	local geoip_code="$1"
	local geoip_type_flag=""
	local geoip_path="$(config_t_get global_rules v2ray_location_asset)"
	geoip_path="${geoip_path%*/}/geoip.dat"
	[ -e "$geoip_path" ] || { echo ""; return; }
	case "$2" in
		"ipv4") geoip_type_flag="-ipv6=false" ;;
		"ipv6") geoip_type_flag="-ipv4=false" ;;
	esac
	if type geoview &> /dev/null; then
		geoview -input "$geoip_path" -list "$geoip_code" $geoip_type_flag -lowmem=true
	else
		echo ""
	fi
}

get_singbox_geoip() {
	local geoip_code="$1"
	local geoip_path=$(config_t_get global_singbox geoip_path)
	[ -e "$geoip_path" ] || { echo ""; return; }
	local has_geoip_tools=$($(first_type $(config_t_get global_app sing_box_file) sing-box) geoip | grep "GeoIP tools")
	if [ -n "${has_geoip_tools}" ]; then
		[ -f "${geoip_path}" ] && local geoip_md5=$(md5sum ${geoip_path} | awk '{print $1}')
		local output_file="${TMP_PATH2}/geoip-${geoip_md5}-${geoip_code}.json"
		[ ! -f ${output_file} ] && $(first_type $(config_t_get global_app sing_box_file) sing-box) geoip -f "${geoip_path}" export "${geoip_code}" -o "${output_file}"
		case "$2" in
			ipv4)
				cat ${output_file} | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | awk -F '"' '{print $2}' | sed -e "/^$/d"
			;;
			ipv6)
				cat ${output_file} | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | awk -F '"' '{print $2}' | sed -e "/^$/d"
			;;
		esac
	else
		echo ""
	fi
}

set_cache_var() {
	local key="${1}"
	shift 1
	local val="$@"
	[ -n "${key}" ] && [ -n "${val}" ] && {
		sed -i "/${key}=/d" $TMP_PATH/var >/dev/null 2>&1
		echo "${key}=\"${val}\"" >> $TMP_PATH/var
		eval ${key}=\"${val}\"
	}
}
get_cache_var() {
	local key="${1}"
	[ -n "${key}" ] && [ -s "$TMP_PATH/var" ] && {
		echo $(cat $TMP_PATH/var | grep "^${key}=" | awk -F '=' '{print $2}' | tail -n 1 | awk -F'"' '{print $2}')
	}
}

eval_cache_var() {
	[ -s "$TMP_PATH/var" ] && eval $(cat "$TMP_PATH/var")
}

has_1_65535() {
	local val="$1"
	val=${val//:/-}
	case ",$val," in
		*,1-65535,*) return 0 ;;
		*) return 1 ;;
	esac
}

run_xray() {
	local flag node redir_port tcp_proxy_way socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port direct_dns_query_strategy remote_dns_protocol remote_dns_udp_server remote_dns_tcp_server remote_dns_doh remote_dns_client_ip remote_dns_detour remote_fakedns remote_dns_query_strategy dns_cache write_ipset_direct
	local loglevel log_file config_file
	local _extra_param=""
	eval_set_val $@
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	if [ "$type" != "xray" ]; then
		local bin=$(first_type $(config_t_get global_app xray_file) xray)
		[ -n "$bin" ] && type="xray"
	fi
	[ -z "$type" ] && return 1
	[ -n "$log_file" ] || local log_file="/dev/null"
	[ -z "$loglevel" ] && local loglevel=$(config_t_get global loglevel "warning")
	[ -n "$flag" ] && pgrep -af "$TMP_BIN_PATH" | awk -v P1="${flag}" 'BEGIN{IGNORECASE=1}$0~P1{print $1}' | xargs kill -9 >/dev/null 2>&1
	[ -n "$flag" ] && _extra_param="${_extra_param} -flag $flag"
	[ -n "$socks_address" ] && _extra_param="${_extra_param} -local_socks_address $socks_address"
	[ -n "$socks_port" ] && _extra_param="${_extra_param} -local_socks_port $socks_port"
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -local_socks_username $socks_username -local_socks_password $socks_password"
	[ -n "$http_address" ] && _extra_param="${_extra_param} -local_http_address $http_address"
	[ -n "$http_port" ] && _extra_param="${_extra_param} -local_http_port $http_port"
	[ -n "$http_username" ] && [ -n "$http_password" ] && _extra_param="${_extra_param} -local_http_username $http_username -local_http_password $http_password"

	[ -n "$dns_listen_port" ] && {
		_extra_param="${_extra_param} -dns_listen_port ${dns_listen_port}"
		[ -n "$dns_cache" ] && _extra_param="${_extra_param} -dns_cache ${dns_cache}"

		local _dns=$(get_first_dns AUTO_DNS 53 | sed 's/#/:/g')
		local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
		local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')

		DIRECT_DNS_UDP_SERVER=${_dns_address}
		DIRECT_DNS_UDP_PORT=${_dns_port}

		[ "${write_ipset_direct}" = "1" ] && {
			direct_dnsmasq_listen_port=$(get_new_port $(expr $dns_listen_port + 1) udp)
			local set_flag="${flag}"
			local direct_ipset_conf=${GLOBAL_ACL_PATH}/dns_${flag}_direct.conf
			[ -n "$(echo ${flag} | grep '^acl')" ] && {
				direct_ipset_conf=${TMP_ACL_PATH}/${sid}/dns_${flag}_direct.conf
				set_flag=$(echo ${flag} | awk -F '_' '{print $2}')
			}
			if [ "${nftflag}" = "1" ]; then
				local direct_nftset="4#inet#passwall2#passwall2_${set_flag}_white,6#inet#passwall2#passwall2_${set_flag}_white6"
			else
				local direct_ipset="passwall2_${set_flag}_white,passwall2_${set_flag}_white6"
			fi
			run_ipset_dns_server listen_port=${direct_dnsmasq_listen_port} server_dns=${AUTO_DNS} ipset="${direct_ipset}" nftset="${direct_nftset}" config_file=${direct_ipset_conf}
			DIRECT_DNS_UDP_PORT=${direct_dnsmasq_listen_port}
			DIRECT_DNS_UDP_SERVER="127.0.0.1"
			[ -n "${direct_ipset}" ] && _extra_param="${_extra_param} -direct_ipset ${direct_ipset}"
			[ -n "${direct_nftset}" ] && _extra_param="${_extra_param} -direct_nftset ${direct_nftset}"
		}
		_extra_param="${_extra_param} -direct_dns_udp_port ${DIRECT_DNS_UDP_PORT} -direct_dns_udp_server ${DIRECT_DNS_UDP_SERVER} -direct_dns_query_strategy ${direct_dns_query_strategy}"
		
		DNS_REMOTE_ARGS=""
		case "$remote_dns_protocol" in
			udp)
				local _dns=$(get_first_dns remote_dns_udp_server 53 | sed 's/#/:/g')
				local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
				local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
				DNS_REMOTE_ARGS="-remote_dns_udp_port ${_dns_port} -remote_dns_udp_server ${_dns_address}"
			;;
			tcp)
				local _dns=$(get_first_dns remote_dns_tcp_server 53 | sed 's/#/:/g')
				local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
				local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
				DNS_REMOTE_ARGS="-remote_dns_tcp_port ${_dns_port} -remote_dns_tcp_server ${_dns_address}"
			;;
			doh)
				local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
				local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
				#local _doh_host_port=$(echo $_doh_url | sed "s/https:\/\///g" | awk -F '/' '{print $1}')
				local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
				local is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
				local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
				[ -z "${_doh_port}" ] && _doh_port=443
				local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
				[ "${is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
				DNS_REMOTE_ARGS="-remote_dns_doh_port ${_doh_port} -remote_dns_doh_url ${_doh_url} -remote_dns_doh_host ${_doh_host}"
				[ -n "$_doh_bootstrap" ] && DNS_REMOTE_ARGS="${DNS_REMOTE_ARGS} -remote_dns_doh_ip ${_doh_bootstrap}"
			;;
		esac
		[ -n "$remote_dns_detour" ] && DNS_REMOTE_ARGS="${DNS_REMOTE_ARGS} -remote_dns_detour ${remote_dns_detour}"
		[ -n "$remote_dns_query_strategy" ] && DNS_REMOTE_ARGS="${DNS_REMOTE_ARGS} -remote_dns_query_strategy ${remote_dns_query_strategy}"
		[ -n "$remote_dns_client_ip" ] && DNS_REMOTE_ARGS="${DNS_REMOTE_ARGS} -remote_dns_client_ip ${remote_dns_client_ip}"
		[ "$remote_fakedns" = "1" ] && _extra_param="${_extra_param} -remote_dns_fake 1 -remote_dns_fake_strategy ${remote_dns_query_strategy}"

		local independent_dns
		if [ -z "${independent_dns}" ]; then
			_extra_param="${_extra_param} ${DNS_REMOTE_ARGS}"
		else
			dns_remote_listen_port=$(get_new_port $(expr ${direct_dnsmasq_listen_port:-${dns_listen_port}} + 1) udp)
			V2RAY_DNS_REMOTE_CONFIG="${TMP_PATH}/${flag}_dns_remote.json"
			V2RAY_DNS_REMOTE_LOG="${TMP_PATH}/${flag}_dns_remote.log"
			V2RAY_DNS_REMOTE_LOG="/dev/null"
			DNS_REMOTE_ARGS="${DNS_REMOTE_ARGS} -dns_out_tag remote -dns_listen_port ${dns_remote_listen_port} -remote_dns_outbound_socks_address 127.0.0.1 -remote_dns_outbound_socks_port ${socks_port}"
			
			lua $UTIL_XRAY gen_dns_config ${DNS_REMOTE_ARGS} > $V2RAY_DNS_REMOTE_CONFIG
			ln_run "$(first_type $(config_t_get global_app ${type}_file) ${type})" ${type} $V2RAY_DNS_REMOTE_LOG run -c "$V2RAY_DNS_REMOTE_CONFIG"
			_extra_param="${_extra_param} -remote_dns_udp_port ${dns_remote_listen_port} -remote_dns_udp_server 127.0.0.1 -remote_dns_query_strategy ${remote_dns_query_strategy}"
		fi
	}
	[ -n "${redir_port}" ] && {
		_extra_param="${_extra_param} -redir_port ${redir_port}"
		set_cache_var "node_${node}_redir_port" "${redir_port}"
		[ -n "${tcp_proxy_way}" ] && _extra_param="${_extra_param} -tcp_proxy_way ${tcp_proxy_way}"
	}

	lua $UTIL_XRAY gen_config -node $node -loglevel $loglevel ${_extra_param} > $config_file
	ln_run "$(first_type $(config_t_get global_app ${type}_file) ${type})" ${type} $log_file run -c "$config_file"
}

run_singbox() {
	local flag node redir_port tcp_proxy_way socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port direct_dns_query_strategy remote_dns_protocol remote_dns_udp_server remote_dns_tcp_server remote_dns_doh remote_dns_client_ip remote_dns_detour remote_fakedns remote_dns_query_strategy dns_cache write_ipset_direct
	local loglevel log_file config_file
	local _extra_param=""
	eval_set_val $@
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	[ -z "$type" ] && return 1
	[ -n "$log_file" ] || local log_file="/dev/null"
	_extra_param="${_extra_param} -log 1 -logfile ${log_file}"
	if [ "$log_file" = "/dev/null" ]; then
		_extra_param="${_extra_param} -log 0"
	else
		_extra_param="${_extra_param} -log 1 -logfile ${log_file}"
	fi
	[ -z "$loglevel" ] && local loglevel=$(config_t_get global loglevel "warn")
	[ "$loglevel" = "warning" ] && loglevel="warn"
	_extra_param="${_extra_param} -loglevel $loglevel"
	
	_extra_param="${_extra_param} -tags $($(first_type $(config_t_get global_app sing_box_file) sing-box) version | grep 'Tags:' | awk '{print $2}')"
	
	[ -n "$flag" ] && pgrep -af "$TMP_BIN_PATH" | awk -v P1="${flag}" 'BEGIN{IGNORECASE=1}$0~P1{print $1}' | xargs kill -9 >/dev/null 2>&1
	[ -n "$flag" ] && _extra_param="${_extra_param} -flag $flag"
	[ -n "$socks_address" ] && _extra_param="${_extra_param} -local_socks_address $socks_address"
	[ -n "$socks_port" ] && _extra_param="${_extra_param} -local_socks_port $socks_port"
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -local_socks_username $socks_username -local_socks_password $socks_password"
	[ -n "$http_address" ] && _extra_param="${_extra_param} -local_http_address $http_address"
	[ -n "$http_port" ] && _extra_param="${_extra_param} -local_http_port $http_port"
	[ -n "$http_username" ] && [ -n "$http_password" ] && _extra_param="${_extra_param} -local_http_username $http_username -local_http_password $http_password"

	[ -n "$dns_listen_port" ] && {
		local _dns=$(get_first_dns AUTO_DNS 53 | sed 's/#/:/g')
		local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
		local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')

		DIRECT_DNS_UDP_SERVER=${_dns_address}
		DIRECT_DNS_UDP_PORT=${_dns_port}

		[ "${write_ipset_direct}" = "1" ] && {
			direct_dnsmasq_listen_port=$(get_new_port $(expr $dns_listen_port + 1) udp)
			local set_flag="${flag}"
			local direct_ipset_conf=${GLOBAL_ACL_PATH}/dns_${flag}_direct.conf
			[ -n "$(echo ${flag} | grep '^acl')" ] && {
				direct_ipset_conf=${TMP_ACL_PATH}/${sid}/dns_${flag}_direct.conf
				set_flag=$(echo ${flag} | awk -F '_' '{print $2}')
			}
			if [ "${nftflag}" = "1" ]; then
				local direct_nftset="4#inet#passwall2#passwall2_${set_flag}_white,6#inet#passwall2#passwall2_${set_flag}_white6"
			else
				local direct_ipset="passwall2_${set_flag}_white,passwall2_${set_flag}_white6"
			fi
			run_ipset_dns_server listen_port=${direct_dnsmasq_listen_port} server_dns=${AUTO_DNS} ipset="${direct_ipset}" nftset="${direct_nftset}" config_file=${direct_ipset_conf}
			DIRECT_DNS_UDP_PORT=${direct_dnsmasq_listen_port}
			DIRECT_DNS_UDP_SERVER="127.0.0.1"
			[ -n "${direct_ipset}" ] && _extra_param="${_extra_param} -direct_ipset ${direct_ipset}"
			[ -n "${direct_nftset}" ] && _extra_param="${_extra_param} -direct_nftset ${direct_nftset}"
		}
		_extra_param="${_extra_param} -direct_dns_udp_port ${DIRECT_DNS_UDP_PORT} -direct_dns_udp_server ${DIRECT_DNS_UDP_SERVER} -direct_dns_query_strategy ${direct_dns_query_strategy}"

		case "$remote_dns_protocol" in
			udp)
				local _dns=$(get_first_dns remote_dns_udp_server 53 | sed 's/#/:/g')
				local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
				local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
				_extra_param="${_extra_param} -remote_dns_udp_port ${_dns_port} -remote_dns_udp_server ${_dns_address}"
			;;
			tcp)
				local _dns=$(get_first_dns remote_dns_tcp_server 53 | sed 's/#/:/g')
				local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
				local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
				_extra_param="${_extra_param} -remote_dns_tcp_port ${_dns_port} -remote_dns_tcp_server ${_dns_address}"
			;;
			doh)
				local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
				local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
				#local _doh_host_port=$(echo $_doh_url | sed "s/https:\/\///g" | awk -F '/' '{print $1}')
				local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
				local is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
				local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
				[ -z "${_doh_port}" ] && _doh_port=443
				local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
				[ "${is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
				[ -n "$_doh_bootstrap" ] && _extra_param="${_extra_param} -remote_dns_doh_ip ${_doh_bootstrap}"
				_extra_param="${_extra_param} -remote_dns_doh_port ${_doh_port} -remote_dns_doh_url ${_doh_url} -remote_dns_doh_host ${_doh_host}"
			;;
		esac

		[ -n "$remote_dns_detour" ] && _extra_param="${_extra_param} -remote_dns_detour ${remote_dns_detour}"
		[ -n "$remote_dns_query_strategy" ] && _extra_param="${_extra_param} -remote_dns_query_strategy ${remote_dns_query_strategy}"
		[ -n "$remote_dns_client_ip" ] && _extra_param="${_extra_param} -remote_dns_client_ip ${remote_dns_client_ip}"

		[ -n "$dns_listen_port" ] && _extra_param="${_extra_param} -dns_listen_port ${dns_listen_port}"
		[ -n "$dns_cache" ] && _extra_param="${_extra_param} -dns_cache ${dns_cache}"
		[ "$remote_fakedns" = "1" ] && _extra_param="${_extra_param} -remote_dns_fake 1"
	}

	[ -n "${redir_port}" ] && {
		_extra_param="${_extra_param} -redir_port ${redir_port}"
		set_cache_var "node_${node}_redir_port" "${redir_port}"
		[ -n "${tcp_proxy_way}" ] && _extra_param="${_extra_param} -tcp_proxy_way ${tcp_proxy_way}"
	}

	lua $UTIL_SINGBOX gen_config -node $node ${_extra_param} > $config_file
	ln_run "$(first_type $(config_t_get global_app sing_box_file) sing-box)" "sing-box" "${log_file}" run -c "$config_file"
}

run_socks() {
	local flag node bind socks_port config_file http_port http_config_file relay_port log_file no_run
	eval_set_val $@
	[ -n "$config_file" ] && [ -z "$(echo ${config_file} | grep $TMP_PATH)" ] && config_file=$TMP_PATH/$config_file
	[ -n "$http_port" ] || http_port=0
	[ -n "$http_config_file" ] && [ -z "$(echo ${http_config_file} | grep $TMP_PATH)" ] && http_config_file=$TMP_PATH/$http_config_file
	if [ -n "$log_file" ] && [ -z "$(echo ${log_file} | grep $TMP_PATH)" ]; then
		log_file=$TMP_PATH/$log_file
	else
		log_file="/dev/null"
	fi
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	local remarks=$(config_n_get $node remarks)
	local server_host=$(config_n_get $node address)
	local server_port=$(config_n_get $node port)
	[ -n "$relay_port" ] && {
		server_host="127.0.0.1"
		server_port=$relay_port
	}
	local error_msg tmp

	if [ -n "$server_host" ] && [ -n "$server_port" ]; then
		check_host $server_host
		[ $? != 0 ] && {
			echolog "  - Socks节点：[$remarks]${server_host} 是非法的服务器地址，无法启动！"
			return 1
		}
		tmp="${server_host}:${server_port}"
	else
		error_msg="某种原因，此 Socks 服务的相关配置已失联，启动中止！"
	fi

	if [ "$type" == "sing-box" ] || [ "$type" == "xray" ]; then
		local protocol=$(config_n_get $node protocol)
		if [ "$protocol" == "_balancing" ] || [ "$protocol" == "_shunt" ] || [ "$protocol" == "_iface" ] || [ "$protocol" == "_urltest" ]; then
			unset error_msg
		fi
	fi

	[ -n "${error_msg}" ] && {
		[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动中止 ${bind}:${socks_port} ${error_msg}"
		return 1
	}
	[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动 ${bind}:${socks_port}"

	case "$type" in
	sing-box)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file="${config_file//SOCKS/HTTP_SOCKS}"
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		[ -n "$relay_port" ] && _extra_param="${_extra_param} -server_host $server_host -server_port $server_port"
		[ "${log_file}" != "/dev/null" ] && {
			local loglevel=$(config_t_get global loglevel "warn")
			[ "$loglevel" = "warning" ] && loglevel="warn"
			_extra_param="${_extra_param} -log 1 -loglevel $loglevel -logfile $log_file"
		}
		[ -n "$no_run" ] && _extra_param="${_extra_param} -no_run 1"
		lua $UTIL_SINGBOX gen_config -flag SOCKS_$flag -node $node -local_socks_address $bind -local_socks_port $socks_port ${_extra_param} > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type $(config_t_get global_app sing_box_file) sing-box)" "sing-box" /dev/null run -c "$config_file"
	;;
	xray)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file="${config_file//SOCKS/HTTP_SOCKS}"
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		[ -n "$relay_port" ] && _extra_param="${_extra_param} -server_host $server_host -server_port $server_port"
		[ -n "$no_run" ] && _extra_param="${_extra_param} -no_run 1"
		lua $UTIL_XRAY gen_config -flag SOCKS_$flag -node $node -local_socks_address $bind -local_socks_port $socks_port ${_extra_param} > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type $(config_t_get global_app xray_file) xray)" "xray" $log_file run -c "$config_file"
	;;
	naiveproxy)
		lua $UTIL_NAIVE gen_config -node $node -run_type socks -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $server_port > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type naive)" naive $log_file "$config_file"
	;;
	ssr)
		lua $UTIL_SS gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $server_port > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type ssr-local)" "ssr-local" $log_file -c "$config_file" -v -u
	;;
	ss)
		[ -n "$no_run" ] || {
			local plugin_sh="${config_file%.json}_plugin.sh"
			local _extra_param="-plugin_sh $plugin_sh"
		}
		lua $UTIL_SS gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $server_port -mode tcp_and_udp ${_extra_param} > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type ss-local)" "ss-local" $log_file -c "$config_file" -v
	;;
	ss-rust)
		local _extra_param
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file="${config_file//SOCKS/HTTP_SOCKS}"
			_extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		[ -n "$no_run" ] || {
			local plugin_sh="${config_file%.json}_plugin.sh"
			_extra_param="${_extra_param:+$_extra_param }-plugin_sh $plugin_sh"
		}
		lua $UTIL_SS gen_config -node $node -local_socks_address $bind -local_socks_port $socks_port -server_host $server_host -server_port $server_port ${_extra_param} > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
	;;
	hysteria2)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file="${config_file//SOCKS/HTTP_SOCKS}"
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		lua $UTIL_HYSTERIA2 gen_config -node $node -local_socks_address $bind -local_socks_port $socks_port -server_host $server_host -server_port $server_port ${_extra_param} > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type $(config_t_get global_app hysteria_file))" "hysteria" $log_file -c "$config_file" client
	;;
	tuic)
		lua $UTIL_TUIC gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $server_port > $config_file
		[ -n "$no_run" ] || ln_run "$(first_type tuic-client)" "tuic-client" $log_file -c "$config_file"
	;;
	esac

	# http to socks
	[ -z "$http_flag" ] && [ "$http_port" != "0" ] && [ -n "$http_config_file" ] && [ "$type" != "sing-box" ] && [ "$type" != "xray" ] && [ "$type" != "socks" ] && {
		local bin=$(first_type $(config_t_get global_app sing_box_file) sing-box)
		if [ -n "$bin" ]; then
			type="sing-box"
			lua $UTIL_SINGBOX gen_proto_config -local_http_port $http_port -server_proto socks -server_address "127.0.0.1" -server_port $socks_port -server_username $_username -server_password $_password > $http_config_file
			[ -n "$no_run" ] || ln_run "$bin" ${type} /dev/null run -c "$http_config_file"
		else
			bin=$(first_type $(config_t_get global_app xray_file) xray)
			[ -n "$bin" ] && type="xray"
			[ -z "$type" ] && return 1
			lua $UTIL_XRAY gen_proto_config -local_http_port $http_port -server_proto socks -server_address "127.0.0.1" -server_port $socks_port -server_username $_username -server_password $_password > $http_config_file
			[ -n "$no_run" ] || ln_run "$bin" ${type} /dev/null run -c "$http_config_file"
		fi
	}
	unset http_flag

	[ -z "$no_run" ] && [ "${server_host}" != "127.0.0.1" ] && [ "$type" != "sing-box" ] && [ "$type" != "xray" ] && echo "${node}" >> $TMP_PATH/direct_node_list
}

socks_node_switch() {
	local flag new_node
	eval_set_val $@
	[ -n "$flag" ] && [ -n "$new_node" ] && {
		local prefix pf filename
		# 结束 SS 插件进程
		for prefix in "" "HTTP_"; do
			pf="$TMP_PATH/${prefix}SOCKS_${flag}_plugin.pid"
			[ -s "$pf" ] && kill -9 "$(head -n1 "$pf")" >/dev/null 2>&1
		done

		pgrep -af "$TMP_BIN_PATH" | awk -v P1="${flag}" 'BEGIN{IGNORECASE=1}$0~P1 && !/acl\/|acl_/{print $1}' | xargs kill -9 >/dev/null 2>&1
		for prefix in "" "HTTP_" "HTTP2"; do
			rm -rf "$TMP_PATH/${prefix}SOCKS_${flag}"*
		done

		for filename in $(ls ${TMP_SCRIPT_FUNC_PATH}); do
			cmd=$(cat ${TMP_SCRIPT_FUNC_PATH}/${filename})
			[ -n "$(echo $cmd | grep "${flag}")" ] && rm -f ${TMP_SCRIPT_FUNC_PATH}/${filename}
		done
		local bind_local=$(config_n_get $flag bind_local 0)
		local bind="0.0.0.0"
		[ "$bind_local" = "1" ] && bind="127.0.0.1"
		local port=$(config_n_get $flag port)
		local config_file="SOCKS_${flag}.json"
		local log_file="SOCKS_${flag}.log"
		local log=$(config_n_get $flag log 1)
		[ "$log" == "0" ] && log_file=""
		local http_port=$(config_n_get $flag http_port 0)
		local http_config_file="HTTP2SOCKS_${flag}.json"
		LOG_FILE="/dev/null"
		run_socks flag=$flag node=$new_node bind=$bind socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file log_file=$log_file
		set_cache_var "socks_${flag}" "$new_node"
		local USE_TABLES=$(get_cache_var "USE_TABLES")
		[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh filter_direct_node_list
	}
}

run_global() {
	[ -z "$NODE" ] && return 1
	TYPE=$(echo $(config_n_get $NODE type) | tr 'A-Z' 'a-z')
	[ -z "$TYPE" ] && return 1
	mkdir -p ${GLOBAL_ACL_PATH}

	if [ $PROXY_IPV6 == "1" ]; then
		echolog "开启实验性IPv6透明代理(TProxy)，请确认您的节点及类型支持IPv6！"
	fi

	TUN_DNS_PORT=15353
	TUN_DNS="127.0.0.1#${TUN_DNS_PORT}"

	V2RAY_ARGS="flag=global node=$NODE redir_port=$REDIR_PORT tcp_proxy_way=${TCP_PROXY_WAY}"
	V2RAY_ARGS="${V2RAY_ARGS} dns_listen_port=${TUN_DNS_PORT} direct_dns_query_strategy=${DIRECT_DNS_QUERY_STRATEGY} remote_dns_query_strategy=${REMOTE_DNS_QUERY_STRATEGY} dns_cache=${DNS_CACHE}"
	local msg="${TUN_DNS} （直连DNS：${AUTO_DNS}"

	[ -n "$REMOTE_DNS_PROTOCOL" ] && {
		V2RAY_ARGS="${V2RAY_ARGS} remote_dns_protocol=${REMOTE_DNS_PROTOCOL} remote_dns_detour=${REMOTE_DNS_DETOUR}"
		case "$REMOTE_DNS_PROTOCOL" in
			udp*)
				V2RAY_ARGS="${V2RAY_ARGS} remote_dns_udp_server=${REMOTE_DNS}"
				msg="${msg} 远程DNS：${REMOTE_DNS}"
			;;
			tcp)
				V2RAY_ARGS="${V2RAY_ARGS} remote_dns_tcp_server=${REMOTE_DNS}"
				msg="${msg} 远程DNS：${REMOTE_DNS}"
			;;
			doh)
				REMOTE_DNS_DOH=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
				V2RAY_ARGS="${V2RAY_ARGS} remote_dns_doh=${REMOTE_DNS_DOH}"
				msg="${msg} 远程DNS：${REMOTE_DNS_DOH}"
			;;
		esac
		[ "$REMOTE_FAKEDNS" = "1" ] && {
			V2RAY_ARGS="${V2RAY_ARGS} remote_fakedns=1"
			msg="${msg} + FakeDNS "
		}
		
		local _remote_dns_client_ip=$(config_t_get global remote_dns_client_ip)
		[ -n "${_remote_dns_client_ip}" ] && V2RAY_ARGS="${V2RAY_ARGS} remote_dns_client_ip=${_remote_dns_client_ip}"
	}
	msg="${msg}）"
	echolog ${msg}

	V2RAY_CONFIG=${GLOBAL_ACL_PATH}/global.json
	V2RAY_LOG=${GLOBAL_ACL_PATH}/global.log
	[ "$(config_t_get global log_node 1)" != "1" ] && V2RAY_LOG="/dev/null"
	V2RAY_ARGS="${V2RAY_ARGS} log_file=${V2RAY_LOG} config_file=${V2RAY_CONFIG}"

	node_socks_port=$(config_t_get global node_socks_port 1070)
	node_socks_bind_local=$(config_t_get global node_socks_bind_local 1)
	node_socks_bind="127.0.0.1"
	[ "${node_socks_bind_local}" != "1" ] && node_socks_bind="0.0.0.0"
	V2RAY_ARGS="${V2RAY_ARGS} socks_address=${node_socks_bind} socks_port=${node_socks_port}"
	set_cache_var "GLOBAL_SOCKS_server" "127.0.0.1:$node_socks_port"

	node_http_port=$(config_t_get global node_http_port 0)
	[ "$node_http_port" != "0" ] && V2RAY_ARGS="${V2RAY_ARGS} http_port=${node_http_port}"

	V2RAY_ARGS="${V2RAY_ARGS} write_ipset_direct=${WRITE_IPSET_DIRECT}"

	local run_func
	[ -n "${XRAY_BIN}" ] && run_func="run_xray"
	[ -n "${SINGBOX_BIN}" ] && run_func="run_singbox"
	if [ "${TYPE}" = "xray" ] && [ -n "${XRAY_BIN}" ]; then
		run_func="run_xray"
	elif [ "${TYPE}" = "sing-box" ] && [ -n "${SINGBOX_BIN}" ]; then
		run_func="run_singbox"
	fi
	
	${run_func} ${V2RAY_ARGS}

	local RUN_NEW_DNSMASQ=1
	RUN_NEW_DNSMASQ=${DNS_REDIRECT}
	if [ "${RUN_NEW_DNSMASQ}" == "0" ]; then
		#The old logic will be removed in the future.
		#Run a copy dnsmasq instance, DNS hijack that don't need a proxy devices.
		[ "1" = "0" ] && {
			DIRECT_DNSMASQ_PORT=$(get_new_port 11400)
			DIRECT_DNSMASQ_CONF=${GLOBAL_ACL_PATH}/direct_dnsmasq.conf
			DIRECT_DNSMASQ_CONF_PATH=${GLOBAL_ACL_PATH}/direct_dnsmasq.d
			mkdir -p ${DIRECT_DNSMASQ_CONF_PATH}
			lua $APP_PATH/helper_dnsmasq.lua copy_instance -LISTEN_PORT ${DIRECT_DNSMASQ_PORT} -DNSMASQ_CONF ${DIRECT_DNSMASQ_CONF} -TMP_DNSMASQ_PATH ${DIRECT_DNSMASQ_CONF_PATH}
			ln_run "$(first_type dnsmasq)" "dnsmasq_direct" "/dev/null" -C ${DIRECT_DNSMASQ_CONF} -x ${GLOBAL_ACL_PATH}/direct_dnsmasq.pid
			set_cache_var "DIRECT_DNSMASQ_PORT" "${DIRECT_DNSMASQ_PORT}"
		}
		
		#Rewrite the default DNS service configuration
		#Modify the default dnsmasq service
		lua $APP_PATH/helper_dnsmasq.lua stretch
		lua $APP_PATH/helper_dnsmasq.lua add_rule -FLAG "default" -TMP_DNSMASQ_PATH ${GLOBAL_DNSMASQ_CONF_PATH} -DNSMASQ_CONF_FILE ${GLOBAL_DNSMASQ_CONF} \
			-DEFAULT_DNS ${AUTO_DNS} -LOCAL_DNS ${LOCAL_DNS:-${AUTO_DNS}} -TUN_DNS ${TUN_DNS} \
			-NFTFLAG ${nftflag:-0} \
			-NO_LOGIC_LOG ${NO_LOGIC_LOG:-0}
		uci -q add_list dhcp.@dnsmasq[0].addnmount=${GLOBAL_DNSMASQ_CONF_PATH}
		uci -q commit dhcp
		lua $APP_PATH/helper_dnsmasq.lua logic_restart -LOG 1
	else
		#Run a copy dnsmasq instance, DNS hijack for that need proxy devices.
		GLOBAL_DNSMASQ_PORT=$(get_new_port 11400)
		run_copy_dnsmasq flag="default" listen_port=$GLOBAL_DNSMASQ_PORT tun_dns="${TUN_DNS}"
		DNS_REDIRECT_PORT=${GLOBAL_DNSMASQ_PORT}
		#dhcp.leases to hosts
		$APP_PATH/lease2hosts.sh > /dev/null 2>&1 &
	fi

	set_cache_var "ACL_GLOBAL_node" "$NODE"
	set_cache_var "ACL_GLOBAL_redir_port" "$REDIR_PORT"
}

start_socks() {
	[ "$SOCKS_ENABLED" = "1" ] && {
		local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		[ -n "$ids" ] && {
			echolog "分析 Socks 服务的节点配置..."
			for id in $ids; do
				local enabled=$(config_n_get $id enabled 0)
				[ "$enabled" == "0" ] && continue
				local node=$(config_n_get $id node)
				[ -z "$node" ] && continue
				local bind_local=$(config_n_get $id bind_local 0)
				local bind="0.0.0.0"
				[ "$bind_local" = "1" ] && bind="127.0.0.1"
				local port=$(config_n_get $id port)
				local config_file="SOCKS_${id}.json"
				local log_file="SOCKS_${id}.log"
				local log=$(config_n_get $id log 1)
				[ "$log" == "0" ] && log_file=""
				local http_port=$(config_n_get $id http_port 0)
				local http_config_file="HTTP2SOCKS_${id}.json"
				run_socks flag=$id node=$node bind=$bind socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file log_file=$log_file
				set_cache_var "socks_${id}" "$node"

				#自动切换逻辑
				local enable_autoswitch=$(config_n_get $id enable_autoswitch 0)
				[ "$enable_autoswitch" = "1" ] && $APP_PATH/socks_auto_switch.sh ${id} > /dev/null 2>&1 &
			done
		}
	}
}

clean_log() {
	logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	[ "$logsnum" -gt 1000 ] && {
		echo "" > $LOG_FILE
		echolog "日志文件过长，清空处理！"
	}
}

clean_crontab() {
	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && return
	touch /etc/crontabs/root
	#sed -i "/${CONFIG}/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "/etc/init.d/${CONFIG}" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/rule_update.lua log" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/subscribe.lua start" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1

	pgrep -af "${CONFIG}/" | awk '/tasks\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
	rm -rf /tmp/lock/${CONFIG}_tasks.lock
}

start_crontab() {
	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		start_daemon=$(config_t_get global_delay start_daemon 0)
		[ "$start_daemon" = "1" ] && $APP_PATH/monitor.sh > /dev/null 2>&1 &
	fi

	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && {
		rm -rf "/tmp/lock/${CONFIG}_cron.lock"
		echolog "当前为计划任务自动运行，不重新配置定时任务。"
		return
	}

	clean_crontab

	[ "$ENABLED" != 1 ] && {
		/etc/init.d/cron restart
		return
	}

	stop_week_mode=$(config_t_get global_delay stop_week_mode)
	stop_time_mode=$(config_t_get global_delay stop_time_mode)
	if [ -n "$stop_week_mode" ]; then
		local t="0 $stop_time_mode * * $stop_week_mode"
		[ "$stop_week_mode" = "7" ] && t="0 $stop_time_mode * * *"
		if [ "$stop_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$t /etc/init.d/$CONFIG stop > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "配置定时任务：自动关闭服务。"
	fi

	start_week_mode=$(config_t_get global_delay start_week_mode)
	start_time_mode=$(config_t_get global_delay start_time_mode)
	if [ -n "$start_week_mode" ]; then
		local t="0 $start_time_mode * * $start_week_mode"
		[ "$start_week_mode" = "7" ] && t="0 $start_time_mode * * *"
		if [ "$start_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$t /etc/init.d/$CONFIG start > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "配置定时任务：自动开启服务。"
	fi

	restart_week_mode=$(config_t_get global_delay restart_week_mode)
	restart_time_mode=$(config_t_get global_delay restart_time_mode)
	if [ -n "$restart_week_mode" ]; then
		local t="0 $restart_time_mode * * $restart_week_mode"
		[ "$restart_week_mode" = "7" ] && t="0 $restart_time_mode * * *"
		if [ "$restart_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$t /etc/init.d/$CONFIG restart > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "配置定时任务：自动重启服务。"
	fi

	autoupdate=$(config_t_get global_rules auto_update)
	weekupdate=$(config_t_get global_rules week_update)
	dayupdate=$(config_t_get global_rules time_update)
	if [ "$autoupdate" = "1" ]; then
		local t="0 $dayupdate * * $weekupdate"
		[ "$weekupdate" = "7" ] && t="0 $dayupdate * * *"
		if [ "$weekupdate" = "8" ]; then
			update_loop=1
		else
			echo "$t lua $APP_PATH/rule_update.lua log all cron > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "配置定时任务：自动更新规则。"
	fi

	TMP_SUB_PATH=$TMP_PATH/sub_crontabs
	mkdir -p $TMP_SUB_PATH
	for item in $(uci show ${CONFIG} | grep "=subscribe_list" | cut -d '.' -sf 2 | cut -d '=' -sf 1); do
		if [ "$(config_n_get $item auto_update 0)" = "1" ]; then
			cfgid=$(uci show ${CONFIG}.$item | head -n 1 | cut -d '.' -sf 2 | cut -d '=' -sf 1)
			remark=$(config_n_get $item remark)
			week_update=$(config_n_get $item week_update)
			time_update=$(config_n_get $item time_update)
			echo "$cfgid" >> $TMP_SUB_PATH/${week_update}_${time_update}
			echolog "配置定时任务：自动更新【$remark】订阅。"
		fi
	done

	[ -d "${TMP_SUB_PATH}" ] && {
		for name in $(ls ${TMP_SUB_PATH}); do
			week_update=$(echo $name | awk -F '_' '{print $1}')
			time_update=$(echo $name | awk -F '_' '{print $2}')
			cfgids=$(echo -n $(cat ${TMP_SUB_PATH}/${name}) | sed 's# #,#g')
			local t="0 $time_update * * $week_update"
			[ "$week_update" = "7" ] && t="0 $time_update * * *"
			if [ "$week_update" = "8" ]; then
				update_loop=1
			else
				echo "$t lua $APP_PATH/subscribe.lua start $cfgids cron > /dev/null 2>&1 &" >>/etc/crontabs/root
			fi
		done
		rm -rf $TMP_SUB_PATH
	}

	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		[ "$update_loop" = "1" ] && {
			$APP_PATH/tasks.sh > /dev/null 2>&1 &
			echolog "自动更新：启动循环更新进程。"
		}
	else
		echolog "运行于非代理模式，仅允许服务启停的定时任务。"
	fi

	/etc/init.d/cron restart
}

stop_crontab() {
	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && return
	clean_crontab
	/etc/init.d/cron restart
	#echolog "清除定时执行命令。"
}

add_ip2route() {
	local ip=$(get_host_ip "ipv4" $1)
	[ -z "$ip" ] && {
		echolog "  - 无法解析[${1}]，路由表添加失败！"
		return 1
	}
	local remarks="${1}"
	[ "$remarks" != "$ip" ] && remarks="${1}(${ip})"

	. /lib/functions/network.sh
	local gateway device
	network_get_gateway gateway "$2"
	network_get_device device "$2"
	[ -z "${device}" ] && device="$2"

	if [ -n "${gateway}" ]; then
		route add -host ${ip} gw ${gateway} dev ${device} >/dev/null 2>&1
		echo "$ip" >> $TMP_ROUTE_PATH/${device}
		echolog "  - [${remarks}]添加到接口[${device}]路由表成功！"
	else
		echolog "  - [${remarks}]添加到接口[${device}]路由表失功！原因是找不到[${device}]网关。"
	fi
}

delete_ip2route() {
	[ -d "${TMP_ROUTE_PATH}" ] && {
		for interface in $(ls ${TMP_ROUTE_PATH}); do
			for ip in $(cat ${TMP_ROUTE_PATH}/${interface}); do
				route del -host ${ip} dev ${interface} >/dev/null 2>&1
			done
		done
	}
}

start_haproxy() {
	[ "$(config_t_get global_haproxy balancing_enable 0)" != "1" ] && return
	haproxy_path=$TMP_PATH/haproxy
	haproxy_conf="config.cfg"
	lua $APP_PATH/haproxy.lua -path ${haproxy_path} -conf ${haproxy_conf} -dns ${LOCAL_DNS:-${AUTO_DNS}}
	ln_run "$(first_type haproxy)" haproxy "/dev/null" -f "${haproxy_path}/${haproxy_conf}"
}

run_copy_dnsmasq() {
	local flag listen_port tun_dns
	eval_set_val $@
	local dnsmasq_conf=$TMP_ACL_PATH/$flag/dnsmasq.conf
	local dnsmasq_conf_path=$TMP_ACL_PATH/$flag/dnsmasq.d
	mkdir -p $dnsmasq_conf_path
	lua $APP_PATH/helper_dnsmasq.lua copy_instance -LISTEN_PORT ${listen_port} -DNSMASQ_CONF ${dnsmasq_conf}
	lua $APP_PATH/helper_dnsmasq.lua add_rule -FLAG "${flag}" -TMP_DNSMASQ_PATH ${dnsmasq_conf_path} -DNSMASQ_CONF_FILE ${dnsmasq_conf} \
		-DEFAULT_DNS ${AUTO_DNS} -LOCAL_DNS ${LOCAL_DNS:-${AUTO_DNS}} -TUN_DNS ${tun_dns} \
		-NFTFLAG ${nftflag:-0} \
		-NO_LOGIC_LOG ${NO_LOGIC_LOG:-0}
	ln_run "$(first_type dnsmasq)" "dnsmasq_${flag}" "/dev/null" -C $dnsmasq_conf -x $TMP_ACL_PATH/$flag/dnsmasq.pid
	set_cache_var "ACL_${flag}_dns_port" "${listen_port}"
}

run_ipset_dns_server() {
	if [ -n "$(first_type chinadns-ng)" ]; then
		run_ipset_chinadns_ng $@
	else
		run_ipset_dnsmasq $@
	fi
}

run_ipset_chinadns_ng() {
	local listen_port server_dns ipset nftset config_file
	eval_set_val $@
	[ ! -s "$TMP_ACL_PATH/vpslist" ] && {
		node_servers=$(uci show "${CONFIG}" | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2)
		hosts_foreach "node_servers" host_from_url | grep '[a-zA-Z]$' | sort -u | grep -v "engage.cloudflareclient.com" > $TMP_ACL_PATH/vpslist
	}
	
	[ -n "${ipset}" ] && {
		set_names=$ipset
		vps_set_names="passwall2_vps,passwall2_vps6"
	}
	[ -n "${nftset}" ] && {
		set_names=$(echo ${nftset} | awk -F, '{printf "%s,%s", substr($1,3), substr($2,3)}' | sed 's/#/@/g')
		vps_set_names="inet@passwall2@passwall2_vps,inet@passwall2@passwall2_vps6"
	}
	cat <<-EOF > $config_file
		bind-addr 127.0.0.1
		bind-port ${listen_port}
		china-dns ${server_dns}
		trust-dns ${server_dns}
		filter-qtype 65
		add-tagchn-ip ${set_names}
		default-tag chn
		group vpslist
		group-dnl $TMP_ACL_PATH/vpslist
		group-upstream ${server_dns}
		group-ipset ${vps_set_names}
	EOF
	ln_run "$(first_type chinadns-ng)" "chinadns-ng" "/dev/null" -C $config_file -v
}

run_ipset_dnsmasq() {
	local listen_port server_dns ipset nftset cache_size dns_forward_max config_file
	eval_set_val $@
	cat <<-EOF > $config_file
		port=${listen_port}
		no-poll
		no-resolv
		strict-order
		cache-size=${cache_size:-0}
		dns-forward-max=${dns_forward_max:-1000}
	EOF
	for i in $(echo ${server_dns} | sed "s#,# #g"); do
		echo "server=${i}" >> $config_file
	done
	[ -n "${ipset}" ] && echo "ipset=${ipset}" >> $config_file
	[ -n "${nftset}" ] && echo "nftset=${nftset}" >> $config_file
	ln_run "$(first_type dnsmasq)" "dnsmasq" "/dev/null" -C $config_file
}

kill_all() {
	kill -9 $(pidof "$@") >/dev/null 2>&1
}

acl_app() {
	local items=$(uci show ${CONFIG} | grep "=acl_rule" | cut -d '.' -sf 2 | cut -d '=' -sf 1)
	[ -n "$items" ] && {
		local index=0
		local item
		local redir_port dns_port dnsmasq_port
		local ipt_tmp msg msg2
		redir_port=11200
		dns_port=11300
		dnsmasq_port=${GLOBAL_DNSMASQ_PORT:-11400}
		for item in $items; do
			index=$(expr $index + 1)
			local enabled sid remarks sources interface tcp_no_redir_ports udp_no_redir_ports node direct_dns_query_strategy write_ipset_direct remote_dns_protocol remote_dns remote_dns_doh remote_dns_client_ip remote_dns_detour remote_fakedns remote_dns_query_strategy
			local _ip _mac _iprange _ipset _ip_or_mac source_list config_file
			local sid=$(uci -q show "${CONFIG}.${item}" | grep "=acl_rule" | awk -F '=' '{print $1}' | awk -F '.' '{print $2}')
			[ "$(config_n_get $sid enabled)" = "1" ] || continue
			eval $(uci -q show "${CONFIG}.${item}" | cut -d'.' -sf 3-)

			if [ -n "${sources}" ]; then
				for s in $sources; do
					local s2
					is_iprange=$(lua_api "iprange(\"${s}\")")
					if [ "${is_iprange}" = "true" ]; then
						s2="iprange:${s}"
					elif [ -n "$(echo ${s} | grep '^ipset:')" ]; then
						s2="ipset:${s}"
					else
						_ip_or_mac=$(lua_api "ip_or_mac(\"${s}\")")
						if [ "${_ip_or_mac}" = "ip" ]; then
							s2="ip:${s}"
						elif [ "${_ip_or_mac}" = "mac" ]; then
							s2="mac:${s}"
						fi
					fi
					[ -n "${s2}" ] && source_list="${source_list}\n${s2}"
					unset s2
				done
			else
				source_list="any"
			fi

			local acl_path=${TMP_ACL_PATH}/$sid
			mkdir -p ${acl_path}
			[ -n "${source_list}" ] && echo -e "${source_list}" | sed '/^$/d' > ${acl_path}/source_list

			node=${node:-default}
			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			if has_1_65535 "$tcp_no_redir_ports" && has_1_65535 "$udp_no_redir_ports"; then
				unset node
			fi

			[ -n "$node" ] && {
				tcp_proxy_mode="global"
				udp_proxy_mode="global"
				direct_dns_query_strategy=${direct_dns_query_strategy:-UseIP}
				write_ipset_direct=${write_ipset_direct:-1}
				remote_dns_protocol=${remote_dns_protocol:-tcp}
				remote_dns=${remote_dns:-1.1.1.1}
				[ "$remote_dns_protocol" = "doh" ] && remote_dns=${remote_dns_doh:-https://1.1.1.1/dns-query}
				remote_dns_detour=${remote_dns_detour:-remote}
				remote_fakedns=${remote_fakedns:-0}
				remote_dns_query_strategy=${remote_dns_query_strategy:-UseIPv4}

				local GLOBAL_node=$(get_cache_var "ACL_GLOBAL_node")
				[ -n "${GLOBAL_node}" ] && GLOBAL_redir_port=$(get_cache_var "ACL_GLOBAL_redir_port")

				if [ "$node" = "default" ]; then
					if [ -n "${GLOBAL_node}" ]; then
						set_cache_var "ACL_${sid}_node" "${GLOBAL_node}"
						set_cache_var "ACL_${sid}_redir_port" "${GLOBAL_redir_port}"
						set_cache_var "ACL_${sid}_dns_port" "${GLOBAL_DNSMASQ_PORT}"
						set_cache_var "ACL_${sid}_default" "1"
					else
						echolog "  - 全局节点未启用，跳过【${remarks}】"
					fi
				else
					[ "$(config_get_type $node)" = "nodes" ] && {
						if [ -n "${GLOBAL_node}" ] && [ "$node" = "${GLOBAL_node}" ]; then
							set_cache_var "ACL_${sid}_node" "${GLOBAL_node}"
							set_cache_var "ACL_${sid}_redir_port" "${GLOBAL_redir_port}"
							set_cache_var "ACL_${sid}_dns_port" "${GLOBAL_DNSMASQ_PORT}"
							set_cache_var "ACL_${sid}_default" "1"
						else
							redir_port=$(get_new_port $(expr $redir_port + 1))

							local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
							if [ -n "${type}" ]; then
								config_file=$TMP_ACL_PATH/${node}_TCP_UDP_DNS_${redir_port}.json
								dns_port=$(get_new_port $(expr $dns_port + 1))
								local acl_socks_port=$(get_new_port $(expr $redir_port + $index))
								local run_func
								[ -n "${XRAY_BIN}" ] && run_func="run_xray"
								[ -n "${SINGBOX_BIN}" ] && run_func="run_singbox"
								if [ "${type}" = "xray" ] && [ -n "${XRAY_BIN}" ]; then
									run_func="run_xray"
								elif [ "${type}" = "sing-box" ] && [ -n "${SINGBOX_BIN}" ]; then
									run_func="run_singbox"
								fi
								${run_func} flag=acl_$sid node=$node redir_port=$redir_port tcp_proxy_way=${TCP_PROXY_WAY} socks_address=127.0.0.1 socks_port=$acl_socks_port dns_listen_port=${dns_port} direct_dns_query_strategy=${direct_dns_query_strategy} remote_dns_protocol=${remote_dns_protocol} remote_dns_tcp_server=${remote_dns} remote_dns_udp_server=${remote_dns} remote_dns_doh="${remote_dns}" remote_dns_client_ip=${remote_dns_client_ip} remote_dns_detour=${remote_dns_detour} remote_fakedns=${remote_fakedns} remote_dns_query_strategy=${remote_dns_query_strategy} write_ipset_direct=${write_ipset_direct} config_file=${config_file}
							fi
							dnsmasq_port=$(get_new_port $(expr $dnsmasq_port + 1))
							run_copy_dnsmasq flag="$sid" listen_port=$dnsmasq_port tun_dns="127.0.0.1#${dns_port}"
							#dhcp.leases to hostsMore actions
							$APP_PATH/lease2hosts.sh > /dev/null 2>&1 &

							set_cache_var "ACL_${sid}_node" "$node"
							set_cache_var "ACL_${sid}_redir_port" "$redir_port"
						fi
					}
				fi
			}
			unset enabled sid remarks sources interface tcp_no_redir_ports udp_no_redir_ports node direct_dns_query_strategy write_ipset_direct remote_dns_protocol remote_dns remote_dns_doh remote_dns_client_ip remote_dns_detour remote_fakedns remote_dns_query_strategy 
			unset _ip _mac _iprange _ipset _ip_or_mac source_list config_file
		done
		unset redir_port dns_port dnsmasq_port
	}
}

start() {
	pgrep -f /tmp/etc/passwall2/bin > /dev/null 2>&1 && {
		#echolog "程序已启动，先停止再重新启动!"
		stop
	}
	mkdir -p /tmp/etc /tmp/log $TMP_PATH $TMP_BIN_PATH $TMP_SCRIPT_FUNC_PATH $TMP_ROUTE_PATH $TMP_ACL_PATH $TMP_PATH2
	get_config
	export V2RAY_LOCATION_ASSET=$(config_t_get global_rules v2ray_location_asset "/usr/share/v2ray/")
	export XRAY_LOCATION_ASSET=$V2RAY_LOCATION_ASSET
	export ENABLE_DEPRECATED_GEOSITE=true
	export ENABLE_DEPRECATED_GEOIP=true
	ulimit -n 65535
	start_haproxy
	start_socks
	nftflag=0
	local use_nft=$(config_t_get global_forwarding use_nft 0)
	local USE_TABLES
	if [ "$use_nft" == 0 ]; then
		if [ -n "$(command -v iptables-legacy || command -v iptables)" ] && [ -n "$(command -v ipset)" ] && [ -n "$(dnsmasq --version | grep 'Compile time options:.* ipset')" ]; then
			USE_TABLES="iptables"
		else
			echolog "系统未安装iptables或ipset或Dnsmasq没有开启ipset支持，无法使用iptables+ipset透明代理！"
			if [ -n "$(command -v fw4)" ] && [ -n "$(command -v nft)" ] && [ -n "$(dnsmasq --version | grep 'Compile time options:.* nftset')" ]; then
				echolog "检测到fw4，使用nftables进行透明代理。"
				USE_TABLES="nftables"
				nftflag=1
				config_t_set global_forwarding use_nft 1
				uci -q commit ${CONFIG}
			fi
		fi
	else
		if [ -n "$(dnsmasq --version | grep 'Compile time options:.* nftset')" ]; then
			USE_TABLES="nftables"
			nftflag=1
		else
			echolog "Dnsmasq软件包不满足nftables透明代理要求，如需使用请确保dnsmasq版本在2.87以上并开启nftset支持。"
		fi
	fi

	check_depends $USE_TABLES
	
	[ "$USE_TABLES" = "nftables" ] && {
		dnsmasq_version=$(dnsmasq -v | grep -i "Dnsmasq version " | awk '{print $3}')
		[ "$(expr $dnsmasq_version \>= 2.90)" == 0 ] && echolog "Dnsmasq版本低于2.90，建议升级至2.90及以上版本以避免部分情况下Dnsmasq崩溃问题！"
	}

	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		[ "$(uci -q get dhcp.@dnsmasq[0].dns_redirect)" == "1" ] && {
			uci -q set ${CONFIG}.@global[0].dnsmasq_dns_redirect='1'
			uci -q commit ${CONFIG}
			uci -q set dhcp.@dnsmasq[0].dns_redirect='0'
			uci -q commit dhcp
			lua $APP_PATH/helper_dnsmasq.lua restart -LOG 0
		}
	fi
	[ "$ENABLED_DEFAULT_ACL" == 1 ] && run_global
	[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh start
	set_cache_var "USE_TABLES" "$USE_TABLES"
	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		bridge_nf_ipt=$(sysctl -e -n net.bridge.bridge-nf-call-iptables)
		set_cache_var "bak_bridge_nf_ipt" "$bridge_nf_ipt"
		sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
		[ "$PROXY_IPV6" == "1" ] && {
			bridge_nf_ip6t=$(sysctl -e -n net.bridge.bridge-nf-call-ip6tables)
			set_cache_var "bak_bridge_nf_ip6t" "$bridge_nf_ip6t"
			sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
		}
	fi
	start_crontab
	echolog "运行完成！\n"
}

stop() {
	clean_log
	eval_cache_var
	[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh stop
	delete_ip2route
	# 结束 SS 插件进程
	# kill_all xray-plugin v2ray-plugin obfs-local shadow-tls
	local pid_file pid
	find "$TMP_PATH" -type f -name '*_plugin.pid' 2>/dev/null | while read -r pid_file; do
		read -r pid < "$pid_file"
		if [ -n "$pid" ]; then
			kill -9 "$pid" >/dev/null 2>&1
		fi
	done
	pgrep -f "sleep.*(6s|9s|58s)" | xargs kill -9 >/dev/null 2>&1
	pgrep -af "${CONFIG}/" | awk '! /app\.sh|subscribe\.lua|rule_update\.lua|tasks\.sh|ujail/{print $1}' | xargs kill -9 >/dev/null 2>&1
	unset V2RAY_LOCATION_ASSET
	unset XRAY_LOCATION_ASSET
	stop_crontab
	rm -rf $GLOBAL_DNSMASQ_CONF
	rm -rf $GLOBAL_DNSMASQ_CONF_PATH
	[ "1" = "1" ] && {
		#restore logic
		bak_dnsmasq_dns_redirect=$(config_t_get global dnsmasq_dns_redirect)
		[ -n "${bak_dnsmasq_dns_redirect}" ] && {
			uci -q set dhcp.@dnsmasq[0].dns_redirect="${bak_dnsmasq_dns_redirect}"
			uci -q commit dhcp
			uci -q delete ${CONFIG}.@global[0].dnsmasq_dns_redirect
			uci -q commit ${CONFIG}
		}
		if [ -z "${ACL_default_dns_port}" ] || [ -n "${bak_dnsmasq_dns_redirect}" ]; then
			uci -q del_list dhcp.@dnsmasq[0].addnmount="${GLOBAL_DNSMASQ_CONF_PATH}"
			uci -q commit dhcp
			lua $APP_PATH/helper_dnsmasq.lua restart -LOG 0
		fi
		[ -n "${bak_bridge_nf_ipt}" ] && sysctl -w net.bridge.bridge-nf-call-iptables=${bak_bridge_nf_ipt} >/dev/null 2>&1
		[ -n "${bak_bridge_nf_ip6t}" ] && sysctl -w net.bridge.bridge-nf-call-ip6tables=${bak_bridge_nf_ip6t} >/dev/null 2>&1
	}
	rm -rf $TMP_PATH
	rm -rf /tmp/lock/${CONFIG}_socks_auto_switch*
	rm -rf /tmp/lock/${CONFIG}_lease2hosts*
	echolog "清空并关闭相关程序和缓存完成。"
	exit 0
}

get_config() {
	ENABLED_DEFAULT_ACL=0
	ENABLED=$(config_t_get global enabled 0)
	NODE=$(config_t_get global node)
	[ "$ENABLED" == 1 ] && {
		[ -n "$NODE" ] && [ "$(config_get_type $NODE)" == "nodes" ] && ENABLED_DEFAULT_ACL=1
	}
	ENABLED_ACLS=$(config_t_get global acl_enable 0)
	[ "$ENABLED_ACLS" == 1 ] && {
		[ "$(uci show ${CONFIG} | grep "@acl_rule" | grep "enabled='1'" | wc -l)" == 0 ] && ENABLED_ACLS=0
	}
	SOCKS_ENABLED=$(config_t_get global socks_enabled 0)
	REDIR_PORT=$(echo $(get_new_port 1041 tcp,udp))
	TCP_PROXY_WAY=$(config_t_get global_forwarding tcp_proxy_way redirect)
	TCP_NO_REDIR_PORTS=$(config_t_get global_forwarding tcp_no_redir_ports 'disable')
	UDP_NO_REDIR_PORTS=$(config_t_get global_forwarding udp_no_redir_ports 'disable')
	TCP_REDIR_PORTS=$(config_t_get global_forwarding tcp_redir_ports '22,25,53,143,465,587,853,993,995,80,443')
	UDP_REDIR_PORTS=$(config_t_get global_forwarding udp_redir_ports '1:65535')
	PROXY_IPV6=$(config_t_get global_forwarding ipv6_tproxy 0)
	TCP_PROXY_MODE="global"
	UDP_PROXY_MODE="global"
	LOCALHOST_PROXY=$(config_t_get global localhost_proxy '1')
	CLIENT_PROXY=$(config_t_get global client_proxy '1')
	DIRECT_DNS_QUERY_STRATEGY=$(config_t_get global direct_dns_query_strategy UseIP)
	REMOTE_DNS_PROTOCOL=$(config_t_get global remote_dns_protocol tcp)
	REMOTE_DNS_DETOUR=$(config_t_get global remote_dns_detour remote)
	REMOTE_DNS=$(config_t_get global remote_dns 1.1.1.1:53 | sed 's/#/:/g' | sed -E 's/\:([^:]+)$/#\1/g')
	REMOTE_FAKEDNS=$(config_t_get global remote_fakedns '0')
	REMOTE_DNS_QUERY_STRATEGY=$(config_t_get global remote_dns_query_strategy UseIPv4)
	WRITE_IPSET_DIRECT=$(config_t_get global write_ipset_direct 1)
	DNS_CACHE=$(config_t_get global dns_cache 1)
	DNS_REDIRECT=$(config_t_get global dns_redirect 1)

	RESOLVFILE=/tmp/resolv.conf.d/resolv.conf.auto
	[ -f "${RESOLVFILE}" ] && [ -s "${RESOLVFILE}" ] || RESOLVFILE=/tmp/resolv.conf.auto

	ISP_DNS=$(cat $RESOLVFILE 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | grep -v -E '^(0\.0\.0\.0|127\.0\.0\.1)$' | awk '!seen[$0]++')
	ISP_DNS6=$(cat $RESOLVFILE 2>/dev/null | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | awk -F % '{print $1}' | awk -F " " '{print $2}' | grep -v -Fx ::1 | grep -v -Fx :: | awk '!seen[$0]++')

	DEFAULT_DNSMASQ_CFGID=$(uci show dhcp.@dnsmasq[0] |  awk -F '.' '{print $2}' | awk -F '=' '{print $1}'| head -1)
	DEFAULT_DNS=$(uci show dhcp.@dnsmasq[0] | grep "\.server=" | awk -F '=' '{print $2}' | sed "s/'//g" | tr ' ' '\n' | grep -v "\/" | head -2 | sed ':label;N;s/\n/,/;b label')
	[ -z "${DEFAULT_DNS}" ] && DEFAULT_DNS=$(echo -n $ISP_DNS | tr ' ' '\n' | head -2 | tr '\n' ',' | sed 's/,$//')
	AUTO_DNS=${DEFAULT_DNS:-119.29.29.29}

	DNSMASQ_CONF_DIR=/tmp/dnsmasq.d
	DEFAULT_DNSMASQ_CFGID="$(uci -q show "dhcp.@dnsmasq[0]" | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')"
	if [ -f "/tmp/etc/dnsmasq.conf.$DEFAULT_DNSMASQ_CFGID" ]; then
		DNSMASQ_CONF_DIR="$(awk -F '=' '/^conf-dir=/ {print $2}' "/tmp/etc/dnsmasq.conf.$DEFAULT_DNSMASQ_CFGID")"
		if [ -n "$DNSMASQ_CONF_DIR" ]; then
			DNSMASQ_CONF_DIR=${DNSMASQ_CONF_DIR%*/}
		else
			DNSMASQ_CONF_DIR="/tmp/dnsmasq.d"
		fi
	fi
	set_cache_var GLOBAL_DNSMASQ_CONF ${DNSMASQ_CONF_DIR}/dnsmasq-${CONFIG}.conf
	set_cache_var GLOBAL_DNSMASQ_CONF_PATH ${GLOBAL_ACL_PATH}/dnsmasq.d

	XRAY_BIN=$(first_type $(config_t_get global_app xray_file) xray)
	SINGBOX_BIN=$(first_type $(config_t_get global_app sing_box_file) sing-box)
}

arg1=$1
shift
case $arg1 in
add_ip2route)
	add_ip2route $@
	;;
echolog)
	echolog $@
	;;
get_new_port)
	get_new_port $@
	;;
get_cache_var)
	get_cache_var $@
	;;
set_cache_var)
	set_cache_var $@
	;;
run_socks)
	run_socks $@
	;;
socks_node_switch)
	socks_node_switch $@
	;;
start)
	start
	;;
stop)
	stop
	;;
esac
