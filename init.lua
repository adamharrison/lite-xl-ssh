--mod-version:3
local core = require "core"
local config = require "core.config"
local common = require "core.common"

config.plugins.ssh = common.merge({
  auth = { 
    -- {
    --   host = "localhost",
    --   user = "adam",
    --   password = "..."
    -- },
    -- {
    --   host = "raspberrypi",
    --   user = "adam",
    --   identity = "/home/adam/.ssh/raspberrypi"
    -- } 
  },
  trace = false,
  -- cache stat calls at most up to 10 seconds
  stat_cache = 10
}, config.plugins.ssh)
-- ssh://adam@raspberrypi:/home
local libssh = require "plugins.ssh.libssh"
local old_libssh_open = libssh.file.open
local old_libssh_read = libssh.file.read
function libssh.file:read(bytes)
  if type(bytes) ~= 'string' then return old_libssh_read(self, bytes) end
  if not self.buf then self.buf = {} end
  if not self.len then self.len = 0 end
  bytes = bytes:gsub("^%*", "")
  local target = 0
  if bytes == "line" or bytes == "l" or bytes == "L" then
    if #self.buf > 0 then
      for i,v in ipairs(self.buf) do
        local s = v:find("\n")
        if s then
          target = target + s
          break
        elseif i < #self.buf then
          target = target + #v
        else
          target = 1024*1024*1024*1024
        end
      end
    else
      target = 1024*1024*1024*1024
    end
  elseif bytes == "all" or bytes == "a" then
    target = 1024*1024*1024*1024
  elseif type(bytes) == "number" then
    target = bytes
  else
    error("'" .. bytes .. "' is an unsupported read option for this stream")
  end
  while self.len < target do
    local chunk = assert(old_libssh_read(self, math.min(math.max(target - self.len, 0), 16 * 1024)))
    if not chunk or chunk == "" then break end
    if #chunk > 0 then
      table.insert(self.buf, chunk)
      self.len = self.len + #chunk
      if bytes == "line" or bytes == "l" or bytes == "L" then
        local s = chunk:find("\n")
        if s then target = self.len - #chunk + s end
      end
    end
  end
  if #self.buf == 0 then return nil end
  local str = table.concat(self.buf)
  self.len = math.max(self.len - target, 0)
  self.buf = self.len > 0 and { str:sub(target + 1) } or {}
  return str:sub(1, target + ((bytes == "line" or bytes == "l") and str:byte(target) == 10 and -1 or 0))
end
function libssh.file:lines()
  return function() return self:read("*l") end
end

local function find_auth(user, host)
  for i,v in ipairs(config.plugins.ssh.auth) do
    if v.user == user and v.host == host then
      return v
    end
  end
end

local function trace_print(line, ...)
  if config.plugins.ssh.trace then
    io.stderr:write(line)
    for i,v in ipairs({ ... }) do
      io.stderr:write("\t")
      io.stderr:write(v)
    end
    io.stderr:write("\n")
    io.stderr:flush()
  end
end

local SSH_URL_PATTERN = "^ssh://([^@]+)@([^:]+):?(.-)$"

local ssh = {
  lib = libssh,
  connections = {},
  stats = {}, -- only send one at most every 5 second stat calls
  warned = {},
  connection = function(self, url)
    local user, host, path = url:match(SSH_URL_PATTERN)
    if not user then return nil, url .. ": not an ssh url" end
    local target = user .. "@" .. host
    if not self.connections[target] then 
      local auth = find_auth(user, host)
      if self.warned[target] then return nil end
      self.warned[target] = true
      assert(auth, "can't find auth for " .. target .. "; please enter one into config.plugins.ssh.auth.")
      core.log("opening ssh connection to " .. target)
      if not auth.identity:find("\n") and system.get_file_info(auth.identity) then 
        auth.identity = io.open(auth.identity):read("*all")
      end
      self.connections[target] = assert(libssh.connect(common.merge(auth, { 
        trace = config.plugins.ssh.trace,
        target = target,
        yield = function() return 0.01 end
      })))
    end
    return self.connections[target], path
  end,
  open = function(self, path, mode)
    local connection, remainder = assert(self:connection(path))
    if not connection then return nil, remainder end
    trace_print("> open", remainder, mode)
    return connection:open(remainder, mode)
  end,
  stat = function(self, path)
    local connection, remainder = assert(self:connection(path))
    if not connection then return nil, remainder end
    local target = connection.target .. ":" .. remainder
    if self.stats[target] and (system.get_time() - self.stats[target].time) < config.plugins.ssh.stat_cache then
      return self.stats[target].stat
    end
    trace_print("> stat", remainder, target)
    local stat = connection:stat(remainder)
    self.stats[target] = { time = system.get_time(), stat = stat } 
    return stat
  end,
  opendir = function(self, path)
    local connection, remainder = assert(self:connection(path))
    if not connection then return nil, remainder end
    trace_print("> opendir", remainder)
    return connection:opendir(remainder)
  end,
  mkdir = function(self, path)
    local connection, remainder = assert(self:connection(path))
    if not connection then return nil, remainder end
    trace_print("> mkdir", remainder)
    return connection:mkdir(remainder)
  end,
  rmdir = function(self, path)
    local connection, remainder = assert(self:connection(path))
    if not connection then return nil, remainder end
    trace_print("> rmdir", remainder)
    return connection:rmdir(remainder)
  end,
  realpath = function(self, path)
    local connection, remainder = assert(self:connection(path))
    if not connection then return nil, remainder end
    trace_print("> realpath", remainder)
    return connection:realpath(remainder)
  end,
  remove = function(self, path)
    local connection, remainder = assert(self:connection(path))
    if not connection then return nil, remainder end
    trace_print("> remove", remainder)
    return connection:remove(remainder)
  end,
  rename = function(self, oldpath, newpath)
    local connection, remainder = assert(self:connection(oldpath))
    if not connection then return nil, remainder end
    trace_print("> rename", remainder)
    local user, host, path = newpath:match(SSH_URL_PATTERN)
    if not user or not connection then return nil, "cannot move between ssh targets" end
    return connection:rename(remainder)
  end
}

local old_open = io.open
io.open = function(path, mode)
  if not path:find(SSH_URL_PATTERN) then return old_open(path, mode) end
  return ssh:open(path, mode)
end

local old_normalize_path = common.normalize_path
function common.normalize_path(path)
  if not path:find(SSH_URL_PATTERN) then return old_normalize_path(path) end
  return path
end


local old_is_absolute_path = common.is_absolute_path
function common.is_absolute_path(path)
  return path:find(SSH_URL_PATTERN) or old_is_absolute_path(path)
end

local old_get_file_info = system.get_file_info
function system.get_file_info(path)
  if not path:find(SSH_URL_PATTERN) then return old_get_file_info(path) end
  local stat = ssh:stat(path)
  return stat
end

local old_system_list_dir = system.list_dir 
function system.list_dir(path)
  local user, host, remainder = path:match(SSH_URL_PATTERN)
  if not user then return old_system_list_dir(path) end
  local dir, err = ssh:opendir(path)
  if not dir then return nil end
  local paths = {}
  for file in dir do
    if file.path ~= ".." and file.path ~= "." then
      ssh.stats[user .. '@' .. host .. ":" .. remainder .. file.path] = {
        time = system.get_time(),
        stat = file
      }
      trace_print("! stat", file.path, host .. '@' .. user .. ":" .. remainder .. file.path)
      table.insert(paths, file.path)
    end
  end
  return paths
end

local old_system_mkdir = system.mkdir
function system.mkdir(path)
  if not path:find(SSH_URL_PATTERN) then return old_system_mkdir(path) end
  return ssh:mkdir(path)
end

local old_system_rmdir = system.rmdir 
function system.rmdir(path)
  if not path:find(SSH_URL_PATTERN) then return old_system_rmdir(path) end
  return ssh:rmdir(path)
end

local old_absolute_path = system.absolute_path
function system.absolute_path(path)
  if not path:find(SSH_URL_PATTERN) then return old_system_absolute_path(path) end
  local user, host, remainder = path:match(SSH_URL_PATTERN)
  if not user then return nil, path .. ": not an ssh url" end
  return "ssh://" .. user .. "@" .. host .. ":" .. ssh:realpath(path)
end

local old_remove = os.remove
function os.remove(path)
  if not path:find(SSH_URL_PATTERN) then return old_remove(path) end
  return ssh:remove(path)
end

local old_rename = os.rename
function os.rename(oldpath, newpath)
  if not path:find(SSH_URL_PATTERN) then return old_rename(oldpath, newpath) end
  return ssh:rename(oldpath, newpath)
end

return ssh
