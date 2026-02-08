--mod-version:4

local ssh = require "libssh"

local cr = coroutine.create(function()
  local tunnel = assert(ssh.connect({ host = "localhost", user = "adam", password = "", blocking = false }))
  local directory = assert(tunnel:opendir("/home/adam"))
  while true do
    local file = directory:read()
    if not file then break end
    print(file.path)
  end
  local f = assert(tunnel:open("/home/adam/testfile", "wb"))
  f:write("???")
  f:close()
  
end)
while coroutine.status(cr) ~= "dead" do
  coroutine.resume(cr)
end
