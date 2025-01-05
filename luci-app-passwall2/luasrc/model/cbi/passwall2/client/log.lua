local api = require "luci.passwall2.api"
local appname = "passwall2"
local http = require "luci.http"
local fs = api.fs
local sys = api.sys

f = SimpleForm(appname)
f.reset = false
f.submit = false
f:append(Template(appname .. "/log/log"))

fb = SimpleForm('backup-restore')
fb.reset = false
fb.submit = false
s = fb:section(SimpleSection, translate("Backup and Restore"), translate("Backup or Restore Client and Server Configurations.") ..
							"<br><font color='red'>" ..
							translate("Note: Restoring configurations across different versions may cause compatibility issues.") ..
							"</font>")

s.anonymous = true
s:append(Template(appname .. "/log/backup_restore"))

local backup_files = {
    "/etc/config/passwall2",
	"/etc/config/passwall2_server",
	"/usr/share/passwall2/domains_excluded"
}

local file_path = '/tmp/passwall2_upload.tar.gz'
local temp_dir = '/tmp/passwall2_bak'
local fd
http.setfilehandler(function(meta, chunk, eof)
	if not fd and meta and meta.name == "ulfile" and chunk then
		sys.call("rm -rf " .. temp_dir)
		fs.remove(file_path)
		fd = nixio.open(file_path, "w")
		sys.call("echo '' > /tmp/log/passwall2.log")
	end
	if fd and chunk then
		fd:write(chunk)
	end
	if eof and fd then
		fd:close()
		fd = nil
		if fs.access(file_path) then
			api.log(" * PassWall2 配置文件上传成功…")
			sys.call("mkdir -p " .. temp_dir)
			if sys.call("tar -xzf " .. file_path .. " -C " .. temp_dir) == 0 then
				for _, backup_file in ipairs(backup_files) do
					local temp_file = temp_dir .. backup_file
					if fs.access(temp_file) then
						sys.call("cp -f " .. temp_file .. " " .. backup_file)
					end
				end
				api.log(" * PassWall2 配置还原成功…")
				api.log(" * 重启 PassWall2 服务中…\n")
				sys.call('/etc/init.d/passwall2 restart > /dev/null 2>&1 &')
				sys.call('/etc/init.d/passwall2_server restart > /dev/null 2>&1 &')
			else
				api.log(" * PassWall2 配置文件解压失败，请重试！")
			end
		else
			api.log(" * PassWall2 配置文件上传失败，请重试！")
		end
		sys.call("rm -rf " .. temp_dir)
		fs.remove(file_path)
	end
end)

return f, fb
