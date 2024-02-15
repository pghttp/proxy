local postgres = require "postgres"
local ngx = ngx
local bit = require"bit"
local lshift = bit.lshift
local rshift = bit.rshift
local bxor = bit.bxor
local bor = bit.bor
local strbyte = string.byte
local make_message = postgres.make_message
local decode_int32 = postgres.decode_int32
local decode_int16 = postgres.decode_int16
--[[
A structure for constant databases
19960914
Copyright 1996
D. J. Bernstein, djb@pobox.com

A cdb is an associative array: it maps strings (`keys`) to strings
(`data`).

A cdb contains 256 pointers to linearly probed open hash tables. The
hash tables contain pointers to (key,data) pairs. A cdb is stored in
a single file on disk:

  +----------------+---------+-------+-------+-----+---------+
  | p0 p1 ... p255 | records | hash0 | hash1 | ... | hash255 |
  +----------------+---------+-------+-------+-----+---------+

Each of the 256 initial pointers states a position and a length. The
position is the starting byte position of the hash table. The length
is the number of slots in the hash table.

Records are stored sequentially, without special alignment. A record
states a key length, a data length, the key, and the data.

Each hash table slot states a hash value and a byte position. If the
byte position is 0, the slot is empty. Otherwise, the slot points to
a record whose key has that hash value.

Positions, lengths, and hash values are 32-bit quantities, stored in
little-endian form in 4 bytes. Thus a cdb must fit into 4 gigabytes.

A record is located as follows. Compute the hash value of the key in
the record. The hash value modulo 256 is the number of a hash table.
The hash value divided by 256, modulo the length of that table, is a
slot number. Probe that slot, the next higher slot, and so on, until
you find the record or run into an empty slot.

The cdb hash function is `h = ((h << 5) + h) ^ c`, with a starting
hash of 5381.

First 2048 bytes (toc) are always available.

`cdb_find` is a transliteration of `tinycdb`'s eponymous function from c to lua.
]]
local function _decode_int32_le(str, pos)
  local a, b, c, d = strbyte(str, pos, pos+3)
  return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24))
end

local function _cdb_hash(k)
  local h = 5381;
  for i = 1,#k do
      h = bxor(h + lshift(h, 5), strbyte(k, i))
  end
  return h
end

local function cdb_find(cdb, k)
  local klen = #k
  local h = _cdb_hash(k)
  local htidx = (h % 256) * 8  + 1                            -- hash table index in toc
  local n = _decode_int32_le(cdb, htidx + 4)                  -- number of table entries
  if n == 0 then return nil end                               -- key doesn't exist

  local htoffset = _decode_int32_le(cdb, htidx) + 1           -- offset of first hash table entry
  local tabend = htoffset + n * 8 - 1
  local probingslot = htoffset + lshift(rshift(h, 8) % n, 3)  -- starting slot for probing within the hash table

  local recpos, vlen, kk
  repeat
      if _decode_int32_le(cdb, probingslot) == h then         -- this slot has the key's hash
          recpos = _decode_int32_le(cdb, probingslot + 4) + 1 -- record position
          if recpos == 0 then return nil end
          if _decode_int32_le(cdb, recpos) == klen then
              kk = string.sub(cdb, recpos + 8, recpos + 8 + klen - 1)
              if kk == k then
                  vlen = _decode_int32_le(cdb, recpos + 4)
                  return string.sub(cdb, recpos + 8 + klen, recpos + 8 + klen + vlen - 1)
              end
          end
      end
      n = n - 1
      probingslot = probingslot + 8
      if probingslot > tabend then
          -- continue probing from the beginning of the table
          probingslot = htoffset
      end
  -- keep going until we saw all elements in this table
  until n == 0
end

-- M message

-- Decode an M message
-- An M message is: 'M'..in32(length including self)..{16-byte opaque msg_id}..int16(num_params)..({ int32(param_len)..{param_val}, ...} x num_params)
-- msg_id is lookup into api message table
-- Returns: msg_id as a 16-byte string, error
local function _decode_M_msg_header(hdr)
  if hdr:sub(1, 1) == "M" then
    -- A valid M message is at least 23 bytes long: M +int32 + 16bytes + int16
    if #hdr >= 23 then
      -- msg_id is a 16-byte opaque value
      local _id = hdr:sub(6,21)
      -- Validate declared length
      local len, declared = #hdr - 5, decode_int32(hdr:sub(2, 5)) - 4
      if len ~= declared then
        return _id, "Invalid M message: declared length not correct: " .. declared .. "; actual: " .. len
      end
      return _id, nil
    else
      return nil, "Invalid M message: too short"
    end
  else
    -- Not an M message
    return nil, nil
  end
end

-- apimsg is a >P/B/E/S template that requires splicing the bind parameter values in
-- mmsg only contains the bind parameter values that we need to splice into B
-- the location to insert the parameters is after B+4+1+1+numparams:2+{2*numparams}
-- after that, we must update the length of the packet and
-- validate numparams in mmsg to be equal to the template
-- the function assumes that mmsg length is already correctly validated

local function tohexstr(str)
  if str == nil then
    return nil
  end
  return (str:gsub(
    ".",
    function(c)
      return string.format("%02X", string.byte(c))
    end
  ))
end

-- Splices the parameters from the M message into bind message.
-- Keeps the parameter count and types from the B message, letting postgres validate by itself
-- if the parameters passed in from the user are incorrect.
-- Returns a spliced M+PBES packet or error if number of args in B and M does not correspond
local function _M_splice(mmsg, pbes)
  if pbes == nil or #pbes ~= 3 then
    return nil, "PBES message is not of correct length (3)"
  end
  --get the B packet
  local b = pbes[2]
  -- Num params must be equal to the template
  local bnargs = b:sub(8, 9)
  if mmsg:sub(22, 23) ~= bnargs then
    return nil, mmsg:sub(6,21) ..": mmsg:sub(22, 23) ~ bnargs (" .. tohexstr(mmsg:sub(22, 23)) .. ":" .. tohexstr(bnargs) .. ") in " .. tohexstr(mmsg)
  end
  local nargs = decode_int16(bnargs)
  return table.concat(
    {
      pbes[1],
      table.concat(make_message("B", b:sub(6, 9 + nargs * 2 + 2) .. mmsg:sub(24) .. b:sub(10 + nargs * 2 + 2))),
      pbes[3]
    }
  ), nil
end

local function split_pbes(pbes)
  if pbes == nil then return nil end

  local plen = decode_int32(pbes)
  local blen = decode_int32(pbes:sub(5, 8))

  return  { pbes:sub(13, 13 + plen - 1)
          , pbes:sub(13 + plen, 13 + plen + blen - 1)
          , pbes:sub(13 + plen + blen)
          }
end

local function read_query(r)
  r.read_body()
  local s = r.get_body_data()
  if s == nil then
    -- Body might be serialized to a temp file
    s = r.get_body_file()
    if s ~= nil then
      local f = io.open(s, 'rb')
      s = f:read("*all")
      io.close(f)
    end
  end
  local ret = {}
  if s ~= nil then
    ret.request = s
  else
    ret.error = "Invalid or missing query text. Body must contain a single valid SQL query or an M message."
  end
  return ret
end

local function concat_keys(t)
  local keyset = {}
  local n = 0

  for k, _ in pairs(t) do
    n = n + 1
    keyset[n] = k
  end
  return table.concat(keyset, ",")
end

local function output_cors(ngx, origin, pg_headers)
  ngx.header["Access-Control-Allow-Credentials"] = "true"
  ngx.header["Access-Control-Allow-Origin"] = origin
  if pg_headers ~= nil then
    ngx.header["Access-Control-Expose-Headers"] = concat_keys(pg_headers)
  end
end

local function output_full_cors(ngx, origin, headers)
  ngx.header["Access-Control-Allow-Credentials"] = "true"
  ngx.header["Access-Control-Allow-Origin"] = origin
  ngx.header["Access-Control-Allow-Methods"] = "OPTIONS, QUERY, POST"
  ngx.header["Access-Control-Allow-Headers"] = headers
end

local function output_headers(hdrs)
  for h, v in pairs(hdrs) do
    ngx.header[h] = v
  end
end

local function on_or_off_value(ctx_def, var_def, default_value)
  -- ctx takes precedence over var
  if ctx_def ~= nil then
    return ctx_def == 'on'
  elseif var_def ~= nil then
    return var_def == 'on'
  else
    return default_value
  end
end

local function string_value(ctx_def, var_def, default_value)
  if ctx_def ~= nil then
    return ctx_def
  elseif var_def ~= nil then
    return var_def
  else
    return default_value
  end
end

-- Request logging

local reqlog_request_bodies = ngx.shared.reqlog_request_bodies
local reqlog_response_bodies = ngx.shared.reqlog_response_bodies
local reqlog_response_errors = ngx.shared.reqlog_response_errors

local function make_logger(store)
  if store == nil then
    return function(_, _) end
  else
    return function(id, body)
      local prev = store:get(id)
      if prev ~= nil then
        body = prev .. body
      end
      store:set(id, body)
    end
  end
end

local log_request_body = make_logger(reqlog_request_bodies)
local log_response_body = make_logger(reqlog_response_bodies)
local log_response_error = make_logger(reqlog_response_errors)

-- Response streaming

local function make_response_writer(reqid)
  return {
    write_body = function(_, payload, more_data_to_come)
      ngx.print(payload)
      log_response_body(reqid, payload)
    end,
    set_status = function(_, s)
      ngx.status = s
      --TODO: Write to status dictionary
    end
  }
end

local function make_error_response_writer(reqid)
  return {
    write_body = function(_, payload, more_data_to_come)
      -- We only send "DB_ERROR" to the client as it would be a security issue to pass on full pg error
      ngx.print("DB_ERROR")
      log_response_error(reqid, payload)
    end,
    set_status = function(_, s)
      ngx.status = s
      --TODO: Write to status dictionary
    end
  }
end

local null_response_writer = {
  write_body = function(_, _)
  end,
  set_status = function(_, _)
  end
}

local headers, _ = ngx.req.get_headers()
local method = ngx.var.request_method
local origin = headers["Origin"]

if method == "OPTIONS" then
  local cors_headers = headers["Access-Control-Request-Headers"]
  output_full_cors(ngx, origin, cors_headers)
  ngx.status = 204
  return {}
elseif method ~= "QUERY" and method ~= "POST" then
  return {}
end

local rid = ngx.var.request_id
local req = read_query(ngx.req)

local response_writer = make_response_writer(rid)
local error_response_writer = make_error_response_writer(rid)

if not req.error then
  -- Not used at the moment. We could use this to cache most of the vars, but not
  -- sure if all vars will be available at init time, so we'll have to be checking anyway
  -- How expensive are a few ngx.var accessess, anyway?
  -- local reqstate = require"pg_http_vars"
  local ctx_vars = ngx.ctx.pg_vars or {}
  local app_user = ngx.ctx.app_user
  -- sometimes we pass community_id as well in the auth token
  local app_cid = ngx.ctx.app_cid

  local vars = {
    database = string_value(ctx_vars.pg_database, ngx.var.pg_database, nil),
    database_header = on_or_off_value(ctx_vars.pg_database_header, ngx.var.pg_database_header, false),

    api_definitions = string_value(ctx_vars.pg_api, ngx.var.pg_api, nil),

    allow_ad_hoc_query = on_or_off_value(ctx_vars.pg_allow_ad_hoc_query, ngx.var.pg_allow_ad_hoc_query, false),
    allow_copy_in = on_or_off_value(ctx_vars.pg_allow_copy_in, ngx.var.pg_allow_copy_in, false),

    -- User/pwd is per-location; it's a bit faster to set in ngx.ctx than in nginx vars
    user_name = string_value(ctx_vars.pg_user_name, ngx.var.pg_user_name, nil),
    user_password = string_value(ctx_vars.pg_user_password, ngx.var.pg_user_password, nil),

    application_name = string_value(ctx_vars.pg_application_name, ngx.var.pg_application_name, "pg_http:" .. ngx.worker.pid()),
    development_mode = on_or_off_value(ctx_vars.pg_development_mode, ngx.var.pg_development_mode, false),

    -- These will be part of pg_pass, bur for now we must include as variable
    port = string_value(ctx_vars.pg_port, ngx.var.pg_port, 5432),
    host = string_value(ctx_vars.pg_host, ngx.var.pg_host, '127.0.0.1')
  }

  if vars.database_header and headers["pg-database"] ~= nil then
    vars.database = headers["pg-database"]
  end

  if vars.database ~= nil and vars.database ~= "" then
    local db = {
      host = vars.host,
      database = vars.database,
      user = vars.user_name,
      password = vars.user_password,
      port = vars.port,
      application_name = vars.application_name
    }

    -- Check for M-message before we connect
    local msg = nil
    local err_msg = nil
    local ct = headers["Content-Type"]
    if ct == "postgres/message" then
      msg = req.request
      if msg == nil then
        err_msg = "Empty M req.request"
      else
        local m_id, m_err = _decode_M_msg_header(msg)

        log_request_body(rid, msg)

        local api = require"m_messages"[vars.api_definitions]
        -- m_id is set only if the message really starts with M
        if m_id ~=nil and m_err == nil and api ~= nil then
          local pbes = split_pbes(cdb_find(api, m_id))
          if pbes ~= nil then
            local x_msg, splice_err = _M_splice(msg, pbes)
            if x_msg ~= nil then
              msg = x_msg
            else
              err_msg = splice_err
            end
          else
            err_msg = "Non-existent M message id '" .. m_id .."'"
          end
        else
          if api == nil then
              err_msg ="M message API is not loaded"
          elseif m_err ~= nil then
            if m_id == nil then
              m_id = "unknown"
            end
            err_msg = m_err .. " [".. m_id .."]"
          end
        end
      end

      if err_msg ~= nil then
        ngx.header["Content-type"] = "text/plain"
        ngx.status = 500
        ngx.log(ngx.ERR, err_msg)
        ngx.say("Error: invalid request")
        ngx.exit(ngx.OK)
        return
      end

    end

    -- TODO: Check what content-type we are using for ad-hoc query so that we don't have to connect at all if the header is wrong

    if msg == nil and not vars.allow_ad_hoc_query then
      ngx.header["Content-type"] = "text/plain"
      ngx.status = 501
      ngx.log(ngx.ERR, m_err)
      ngx.say("Unsupported request type")
      ngx.exit(ngx.OK)
      return
    end

    -- If we're here we either have a valid M-message or an ad-hoc query, ok to connect
    local pg = postgres.new()
    local hdrs, err = pg:connect(db, ngx.now())

    -- A successful connection returns a table with headers.
    -- If the return value is nil, means we got one of the possible errors from
    -- connection, authentication, processing of the connection message reply.
    if not hdrs then
      ngx.log(ngx.ERR, "Error while connecting: " .. (err or ""))
      ngx.header["Content-type"] = "text/plain"
      ngx.status = 503
      output_cors(ngx, origin)
      ngx.say(err or "Service unavailable")
      ngx.exit(ngx.OK)
    elseif err then
      ngx.log(ngx.ERR, "Error while connecting: " .. err)
      ngx.header["Content-type"] = "text/plain"
      ngx.status = 500
      output_cors(ngx, origin)
      ngx.say("Internal server error")
      ngx.exit(ngx.OK)
    else
      local show_debug_headers = headers["postgres-debug"] == "show headers"
      ngx.header["Content-type"] = "application/octet-stream"
      output_cors(ngx, origin, show_debug_headers and hdrs or nil)

      if show_debug_headers then
        output_headers(hdrs)
      end

      if app_user ~= nil then
        local set_user = "set ecs.usr ='" .. app_user .. "'"
        pg:stream_query(set_user, null_response_writer)
      end
      if app_cid ~= nil then
        local set_cid = "set ecs.cid ='".. app_cid .. "'"
        pg:stream_query(set_cid, null_response_writer)
      end

      if msg ~= nil then
        -- msg is an M message
        pg:buffered_response(msg, response_writer, error_response_writer)
      else
        -- Ad-hoc query
        pg:stream_query(req.request, response_writer, error_response_writer)
      end
      if app_user ~= nil then
        pg:stream_query("set ecs.usr = ''", null_response_writer)
      end
      if app_cid ~= nil then
        pg:stream_query("set ecs.cid =''", null_response_writer)
      end
    end

    pg:set_keepalive()
  else
    ngx.header["Content-type"] = "text/plain"
    ngx.status = 503
    output_cors(ngx, origin)
    ngx.log(ngx.ERR, "No database connection defined for host ".. ngx.var.host)
    ngx.say("Service unavailable: no connection")
    ngx.exit(503)
  end
else
  output_cors(ngx, origin)
  ngx.header["Content-type"] = "text/plain"
  ngx.status = 400
  ngx.say(req.error)
end
