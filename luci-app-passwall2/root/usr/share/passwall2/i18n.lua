if #arg > 0 then
    local api = require "luci.passwall2.api"
    local str = arg[1]
    table.remove(arg, 1)
    print(api.i18n.translatef(str, unpack(arg)))
end
