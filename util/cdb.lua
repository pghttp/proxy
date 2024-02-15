local strbyte = string.byte
local bit = require"bit"
local lshift = bit.lshift
local rshift = bit.rshift
local bor = bit.bor

local _M = {VERSION = "1.0"}
local mt = {__index = _M}

local function _decode_int32_le(str, pos)
    local a, b, c, d = strbyte(str, pos, pos+3)
    return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24))
end

local function _decode_int32(str)
    local d, c, b, a = strbyte(str, 1, 4)
    return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24))
end

local function _cdb_hash(k)
  local h = 5381;
  for i = 1,#k do
      h = bxor(h + lshift(h, 5), strbyte(k, i))
  end
  return h
end

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


local function split_pbes(pbes)
    if pbes == nil then return nil end
  
    local plen = _decode_int32(pbes)
    local blen = _decode_int32(pbes:sub(5, 8))
  
    -- We only want the query text, so start with position 15 and drop the 'P' header
    return pbes:sub(19, 13 + plen - 4)
  end

-- List all keys and values in the cdb
-- We list each hash table in order of the toc:
--    First, we pick up a pointer in the toc
--    If the pointer has length, we iterate the hash table
--    We continue until we saw all 256 pointers
local function cdb_list(cdb)
    local toc_entry, klen = 0, 16                                 -- all keys are 16 bytes
    local kv = {}

    repeat
        local htidx = toc_entry * 8  + 1                            -- toc entry position
        local n = _decode_int32_le(cdb, htidx + 4)                  -- number of table entries
        if n > 0 then                                               -- table has entries

        local htoffset = _decode_int32_le(cdb, htidx) + 1         -- offset of first hash table entry
        local tabend = htoffset + n * 8 - 1
        local probingslot = htoffset                              -- starting slot for probing within the hash table

        local recpos, vlen, kk
        repeat
            recpos = _decode_int32_le(cdb, probingslot + 4) + 1   -- record position
            if recpos == 0 then return nil end                    -- end of this hash table or an error?
            if _decode_int32_le(cdb, recpos) == klen then
                kk = string.sub(cdb, recpos + 8, recpos + 8 + klen - 1)
                vlen = _decode_int32_le(cdb, recpos + 4)
                kv[kk] = string.sub(cdb, recpos + 8 + klen, recpos + 8 + klen + vlen - 1) 
            end
            n = n - 1
            probingslot = probingslot + 8
        -- keep going until we saw all elements in this table
        until n == 0
        end
        toc_entry = toc_entry + 1
    until toc_entry > 255
    return kv
end

local function list_queries(cdb)
    local l = cdb_list(cdb)
    local o = {}
    for k,v in pairs(l) do
        o[k] = split_pbes(v)
    end
    return o
end

_M.find = cdb_find
_M.list = list_queries

return _M