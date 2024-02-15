local bit = require "bit"
local ffi = require "ffi"
local sub = string.sub
local tcp = ngx.socket.tcp
local strbyte = string.byte
local strchar = string.char
local strfind = string.find
local format = string.format
local strrep = string.rep
local null = ngx.null
local band = bit.band
local bxor = bit.bxor
local bor = bit.bor
local lshift = bit.lshift
local rshift = bit.rshift
local tohex = bit.tohex
local unpack = unpack
local setmetatable = setmetatable
local error = error
local tonumber = tonumber
local md5 = ngx.md5
local ffinew = ffi.new
local ffisizeof = ffi.sizeof
local ffistr = ffi.string
local header_cache = require "header_cache"

if not ngx.config or not ngx.config.ngx_lua_version or ngx.config.ngx_lua_version < 9011 then
  error("ngx_lua 0.9.11+ required")
end

local _M = {VERSION = "1.0"}
local mt = {__index = _M}

local STATE_CONNECTED = 1

-- Protocol encoding/decoding

-- INTEGERS
local function _encode_int32(n)
  return strchar(band(rshift(n, 24), 0xff), band(rshift(n, 16), 0xff), band(rshift(n, 8), 0xff), band(n, 0xff))
end

local function _decode_int32(str)
  local d, c, b, a = strbyte(str, 1, 4)
  return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24))
end

local function _decode_int16(str)
  local b, a = strbyte(str, 1, 2)
  return bor(a, lshift(b, 8))
end

-- TODO: Change to an 8-byte string that just reads from cdata and does table.concat.
local function _get_byte8(data, i)
  local a, b, c, d, e, f, g, h = strbyte(data, i, i + 7)
  -- XXX workaround for the lack of 64-bit support in bitop:
  local lo = bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24))
  local hi = bor(e, lshift(f, 8), lshift(g, 16), lshift(h, 24))
  return lo + hi * 4294967296
end

local _len
_len = function(thing, t)
  if t == nil then
    t = type(thing)
  end
  if "string" == t then
    return #thing
  elseif "table" == t then
    local l = 0
    for _idx = 1, #thing do
      local inner = thing[_idx]
      local inner_t = type(inner)
      if inner_t == "string" then
        l = l + #inner
      else
        l = l + _len(inner, inner_t)
      end
    end
    return l
  else
    return error("don't know how to calculate length of " .. tostring(t))
  end
end

local function _FSM(t)
  local default_key = {}
  local a = {default_key = {}}
  local mt = {
    __index = function(t, val)
      return setmetatable(
        {},
        {
          __index = function()
            return a[default_key]
          end
        }
      )
    end
  }

  for _, v in ipairs(t) do
    local state, event, new_state, action = v[1], v[2], v[3], v[4]
    if state == nil then
      a[default_key] = {new_state, action}
    else
      if a[state] == nil then
        a[state] = {}
      end
      if event ~= nil then
        a[state][event] = {new_state, action}
      else
        a[state] =
          setmetatable(
          a[state],
          {
            __index = function()
              return {new_state, action}
            end
          }
        )
      end
    end
  end
  return setmetatable(a, mt)
end

local MSG_TYPE = {
  status = "S",
  auth = "R",
  backend_key = "K",
  ready_for_query = "Z",
  query = "Q",
  notice = "N",
  notification = "A",
  password = "p",
  row_description = "T",
  data_row = "D",
  command_complete = "C",
  error = "E"
}

local ERROR_TYPES = {
  C = "code",
  D = "detail",
  M = "message",
  P = "position",
  S = "severity",
  n = "constraint",
  s = "schema",
  t = "table",
  code = "C",
  detail = "D",
  message = "M",
  position = "P",
  severity = "S",
  constraint = "n",
  schema = "s",
  table = "t"
}

local ZERO = "\0"

local function _connection_id(sock)
  -- This works as long as the layout of ngx_http_lua_socket_tcp_upstream_s
  -- has the upstream connection (ngx_peer_connection_t)
  -- as the ninth pointer in the struct.
  local ptrsize = ffisizeof(ffinew("void *"))
  local userdata = ffistr(sock[1], 9 * ptrsize)
  return _get_byte8(userdata, 8 * ptrsize + 1)
end
-- REQUEST MESSAGES
local function _startup_msg(startup_opt)
  local sp = {
    _encode_int32(0),
    _encode_int32(196608)
  }
  for k, v in pairs(startup_opt) do
    sp[#sp + 1] = k
    sp[#sp + 1] = ZERO
    sp[#sp + 1] = v
    sp[#sp + 1] = ZERO
  end
  sp[#sp + 1] = ZERO
  sp[1] = _encode_int32(_len(sp))

  return sp
end

local function _ssl_message()
  return {
    _encode_int32(8),
    _encode_int32(80877103)
  }
end

local function _message(t, data, len)
  if len == nil then
    len = _len(data)
  end
  len = len + 4
  return {
    t,
    _encode_int32(len),
    data
  }
end

-- REPLIES
local function _type_and_length(hdr)
  return hdr:sub(1, 1), _decode_int32(hdr:sub(2, 5)) - 4
end

local function _parse_error(err_msg)
  local severity, message, detail, position
  local error_data = {}
  local offset = 1
  while offset <= #err_msg do
    local t = err_msg:sub(offset, offset)
    local str = err_msg:match("[^%z]+", offset + 1)
    if not (str) then
      break
    end
    offset = offset + (2 + #str)
    do
      local field = ERROR_TYPES[t]
      if field then
        error_data[field] = str
      end
    end
    if ERROR_TYPES.severity == t then
      severity = str
    elseif ERROR_TYPES.message == t then
      message = str
    elseif ERROR_TYPES.position == t then
      position = str
    elseif ERROR_TYPES.detail == t then
      detail = str
    end
  end
  local msg = tostring(severity) .. ": " .. tostring(message)
  if position then
    msg = tostring(msg) .. " (" .. tostring(position) .. ")"
  end
  if detail then
    msg = tostring(msg) .. "\n" .. tostring(detail)
  end
  return msg, error_data
end

local function _parse_status(msg)
  return msg:match("^([^%z]+)%z([^%z]*)%z$", 1)
end

local function _parse_notification(msg)
  local pid = _decode_int32(msg:sub(1, 4))
  local offset = 4
  local channel, payload = msg:match("^([^%z]+)%z([^%z]*)%z$", offset + 1)
  if not (channel) then
    error("parse_notification: failed to parse notification")
  end
  return {
    operation = "notification",
    pid = pid,
    channel = channel,
    payload = payload
  }
end

-- SEND AND RECEIVE
local function _send(sock, data)
  return sock:send(data)
end

local function _receive(sock, len)
  local bytes, err = sock:receive(len)
  return bytes
end

local function _recv_msg(sock)
  local t, len = _type_and_length(_receive(sock, 5))
  if not (t) then
    error("Malformed message")
  end
  return t, _receive(sock, len)
end

local function _send_ssl_message(sock, ssl_verify, ssl_required, luasec_opts)
  local success, err = _send(sock, _ssl_message())
  if not (success) then
    return nil, err
  end
  local t
  t, err = _receive(sock, 1)
  if not (t) then
    return nil, err
  end
  if t == MSG_TYPE.status then
    return sock:sslhandshake(false, nil, ssl_verify, nil, luasec_opts)
  elseif t == MSG_TYPE.error or ssl_required then
    sock:close()
    return nil, "the server does not support SSL connections"
  else
    return true
  end
end

-- AUTH

local function _cleartext_auth(sock, msg, user, password)
  assert(password, "missing password, required for connect")
  _send(sock, _message(MSG_TYPE.password, {password, ZERO}))
  return true
end

local function _md5_auth(sock, msg, user, password)
  local salt = msg:sub(5, 8)
  assert(password, "missing password, required for connect")
  _send(sock, _message(MSG_TYPE.password, {"md5", md5(md5(password .. user) .. salt), ZERO}))
  return true
end

local function _auth(sock, t, msg, user, password)
  if not (MSG_TYPE.auth == t) then
    sock:close()
    return ("unexpected message during auth: " .. tostring(t))
  end
  local auth_type = _decode_int32(msg)
  if 0 == auth_type then
    return true
  elseif 3 == auth_type then
    return _cleartext_auth(sock, msg, user, password)
  elseif 5 == auth_type then
    return _md5_auth(sock, msg, user, password)
  else
    return ("don't know how to auth: " .. tostring(auth_type))
  end
end

-- PUBLIC METHODS

function _M.new(self)
  local sock, err = tcp()
  if not sock then
    return nil, err
  end
  return setmetatable({sock = sock, header_cache = {}}, mt)
end

function _M.set_timeout(self, timeout)
  local sock = self.sock
  if not sock then
    return nil, "not initialized"
  end

  return sock:settimeout(timeout)
end

function _M.connect(self, opts, time)
  local sock = self.sock
  if not sock then
    return nil, "not initialized"
  end

  local ok, err

  local pool = opts.pool
  local host = opts.host

  local user = opts.user
  local database = opts.database or user

  if host then
    local port = opts.port or 5432
    if pool == nil then
      pool = host .. ":" .. port .. ":" .. database .. ":" .. user
    end
    ok, err = sock:connect(host, port, {pool = pool})
  else
    local path = opts.path
    if not path then
      return nil, 'neither "host" nor "path" options are specified'
    end

    if not pool then
      pool = database .. ":" .. user .. ":" .. path
    end

    ok, err = sock:connect("unix:" .. path, {pool = pool})
  end

  if not ok then
    return nil, "failed to connect: " .. err
  end

  local reused = sock:getreusedtimes()

  local connection_id = _connection_id(sock)
  if reused > 0 then
    self.state = STATE_CONNECTED
    return header_cache[connection_id] or {}
  end

  local success, err

  local ssl = opts.ssl
  if ssl then
    local luasec_opts = {
      key = opts.key,
      cert = opts.cert,
      cafile = opts.cafile
    }
    local ssl_verify = opts.ssl_verify
    local ssl_required = opts.ssl_required
    success, err = _send_ssl_message(sock, ssl_verify, ssl_required, luasec_opts)
    if not (success) then
      return nil, err
    end
  end

  local application_name = opts.application_name

  success, err = _send(sock, _startup_msg({user = user, database = database, application_name = application_name}))
  if not success then
    return nil, err
  end

  local t, msg = _recv_msg(sock)
  if MSG_TYPE.error == t then
    local pg_error = _parse_error(msg)
    return nil, pg_error
  end
  -- Already here we can have an error
  local password = opts.password
  success, err = _auth(sock, t, msg, user, password)
  if not success then
    return nil, err
  end

  -- At this point we've sent the authentication response
  -- From here, we either get the error (E), or we got a list of parameter status (S) messages, followed by K and a Z
  t, msg = _recv_msg(sock)
  if MSG_TYPE.error == t then
    local pg_error = _parse_error(msg)
    return nil, pg_error
  end

  local h = {}
  while true do
    local t, msg = _recv_msg(sock)
    if MSG_TYPE.ready_for_query == t then
      break
    elseif MSG_TYPE.error == t then
      local pg_error = _parse_error(msg)
      return nil, pg_error
    elseif MSG_TYPE.status == t then
      local k, v = _parse_status(msg)
      h[k] = v
    elseif MSG_TYPE.backend_key == t then
      local pid, session = _decode_int32(msg:sub(1, 4)), _decode_int32(msg:sub(5, 8))
      h["backend"] = pid .. "/" .. session
    end
  end

  h["request-time"] = time
  header_cache[connection_id] = h

  self.state = STATE_CONNECTED

  return h
end

function _M.set_keepalive(self, ...)
  local sock = self.sock
  if not sock then
    return nil, "not initialized"
  end

  if self.state ~= STATE_CONNECTED then
    return nil, "cannot be reused in the current connection state: " .. (self.state or "nil")
  end

  self.state = nil
  return sock:setkeepalive(...)
end

local function close(self)
  local sock = self.sock
  if not sock then
    return nil, "not initialized"
  end

  self.state = nil

  --TODO: Move the connection state into the object itself.
  -- self:header_state[_connection_id(sock)] = nil

  return sock:close()
end

local function buffered_response(self, q, sink, error_sink)
  local sock = self.sock
  _send(sock, q)

  local function ignore_message(hdr, tag, len, response_writer)
    _receive(sock, len)
    return true
  end

  local function send_message(hdr, tag, len, response_writer)
    local to_send, chunk_size = len, 65536
    response_writer:write_body(hdr, to_send > 0)
    while to_send > 0 do
      if chunk_size > to_send then
        chunk_size = to_send
      end
      --TODO: Consider what kind of error handling can we do here if _receive returns nil, err
      local msg, err = _receive(sock, chunk_size)
      to_send = to_send - chunk_size
      response_writer:write_body(msg, to_send > 0)
    end
    return true
  end

  local function ignore_message_and_done(hdr, tag, len, response_writer)
    _receive(sock, len)
    return false
  end

  local function set_header_more_data(hdr, tag, len, response_writer)
    _receive(sock, len)
    return true
  end

  local function start_streaming(hdr, tag, len, response_writer)
    response_writer:set_status(200)
    return send_message(hdr, tag, len, response_writer)
  end

  local function no_content(hdr, tag, len, response_writer)
    response_writer:set_status(204)
    return ignore_message_and_done(hdr, tag, len, response_writer)
  end

  local function send_error(hdr, tag, len, response_writer, error_response_writer)
    response_writer:set_status(422)
    return send_message(hdr, tag, len, error_response_writer)
  end

  local state_table = {
    {"B", "Z", "204", no_content},
    {"B", "t", "200", start_streaming},
    {"B", "T", "200", start_streaming},
    {"B", "D", "200", start_streaming},
    {"B", "E", "422", send_error},
    {"B", nil, "B", ignore_message},
    {"200", "D", "200", send_message},
    {"200", "c", "200", set_header_more_data},
    {"200", "T", "200", send_message},
    {"200", "Z", "200", ignore_message_and_done},
    {"200", nil, "200", ignore_message},
    {"204", nil, "204", ignore_message},
    {"422", "Z", "422", ignore_message_and_done},
    {"422", nil, "422", ignore_message},
    {nil, nil, "ERR", ignore_message}
  }

  local stepper = _FSM(state_table)
  local t, len, hdr, stop, msg, action
  local state = "B"
  local keep_looping = true

  while keep_looping do
    hdr = _receive(sock, 5)
    if not hdr then
      break
    end
    t, len = _type_and_length(hdr)
    if not (t) then
      break
    end
    state, action = unpack(stepper[state][t])
    keep_looping, msg = action(hdr, t, len, sink, error_sink)
    if msg ~= nil then
      ngx.log(ngx.WARN, msg)
    end
  end
end

local function _stream_query(self, q, sink, error_sink)
  buffered_response(self, _message(MSG_TYPE.query, {q, ZERO}), sink, error_sink)
end

------ Exports
_M.close = close
_M.buffered_response = buffered_response
_M.stream_query = _stream_query
_M.decode_int16 = _decode_int16
_M.encode_int32 = _encode_int32
_M.decode_int32 = _decode_int32
_M.make_message = _message
return _M
