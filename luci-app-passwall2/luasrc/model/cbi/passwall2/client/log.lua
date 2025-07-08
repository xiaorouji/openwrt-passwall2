local appname = "passwall2"

f = SimpleForm(appname)
f.reset = false
f.submit = false
f:append(Template(appname .. "/log/log"))

return f