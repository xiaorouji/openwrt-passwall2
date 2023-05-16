local _M = {}

local function gh_release_url(self)
	return "https://api.github.com/repos/" .. self.repo .. "/releases/latest"
end

local function gh_pre_release_url(self)
	return "https://api.github.com/repos/" .. self.repo .. "/releases?per_page=1"
end

_M.brook = {
	name = "Brook",
	repo = "txthinking/brook",
	get_url = gh_release_url,
	cmd_version = "-v | awk '{print $3}'",
	zipped = false,
	default_path = "/usr/bin/brook",
	match_fmt_str = "linux_%s$",
	file_tree = {}
}

_M.hysteria = {
	name = "Hysteria",
	repo = "HyNetwork/hysteria",
	get_url = gh_release_url,
	cmd_version = "-v | awk '{print $3}'",
	zipped = false,
	default_path = "/usr/bin/hysteria",
	match_fmt_str = "linux%%-%s$",
	file_tree = {
		armv6 = "arm",
		armv7 = "arm"
	}
}

_M.v2ray = {
	name = "V2ray",
	repo = "v2fly/v2ray-core",
	get_url = gh_pre_release_url,
	cmd_version = "version | awk '{print $2}' | sed -n 1P",
	zipped = true,
	default_path = "/usr/bin/v2ray",
	match_fmt_str = "linux%%-%s",
	file_tree = {
		x86_64 = "64",
		x86    = "32",
		mips   = "mips32",
		mipsel = "mips32le"
	}
}

_M.xray = {
	name = "Xray",
	repo = "XTLS/Xray-core",
	get_url = gh_pre_release_url,
	cmd_version = _M.v2ray.cmd_version,
	zipped = true,
	default_path = "/usr/bin/xray",
	match_fmt_str = _M.v2ray.match_fmt_str,
	file_tree = _M.v2ray.file_tree
}

return _M
