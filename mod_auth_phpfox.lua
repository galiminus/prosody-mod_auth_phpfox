-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2015 Victor Goya
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

local datamanager = require "util.datamanager";
local log = require "util.logger".init("auth_phpfox");
local type = type;
local error = error;
local ipairs = ipairs;
local hashes = require "util.hashes";
local jid_bare = require "util.jid".bare;
local config = require "core.configmanager";
local usermanager = require "core.usermanager";
local new_sasl = require "util.sasl".new;
local nodeprep = require "util.encodings".stringprep.nodeprep;
local hosts = hosts;
local DBI = require "DBI";
local md5 = require "util.hashes".md5;
local sha1 = require "util.hashes".sha1;

local rostermanager = require "core.rostermanager"
local storagemanager = require "core.storagemanager";

local prosody = _G.prosody;

local connection;
local params = module:get_option("auth_sql", module:get_option("phpfox"));

if not params.exclude_view then params.exclude_view = -1; end

local function test_connection()
   if not connection then return nil; end
   if connection:ping() then
      return true;
   else
      module:log("debug", "Database connection closed");
      connection = nil;
   end
end
local function connect()
   if not test_connection() then
      prosody.unlock_globals();
      local dbh, err = DBI.Connect(
         params.driver, params.database,
         params.username, params.password,
         params.host, params.port
                                  );
      prosody.lock_globals();
      if not dbh then
         module:log("debug", "Database connection failed: %s", tostring(err));
         return nil, err;
      end
      module:log("debug", "Successfully connected to database");
      dbh:autocommit(true); -- don't run in transaction
      connection = dbh;
      return connection;
   end
end

do -- process options to get a db connection
   assert(connect());
end

local function getsql(sql, ...)
   if not test_connection() then connect(); end
   -- do prepared statement stuff
   local stmt, err = connection:prepare(sql);
   if not stmt and not test_connection() then error("connection failed"); end
   if not stmt then module:log("error", "QUERY FAILED: %s %s", err, debug.traceback()); return nil, err; end
   -- run query
   local ok, err = stmt:execute(...);
   if not ok and not test_connection() then error("connection failed"); end
   if not ok then return nil, err; end

   return stmt;
end

local function get_user(username)
   local stmt, err = getsql("SELECT * FROM `"..params.prefix.."_user` WHERE `user_name`=?", username);
   if stmt then
      for row in stmt:rows(true) do
         return row;
      end
   end
end

local function get_user_from_id(id)
   local stmt, err = getsql("SELECT * FROM `"..params.prefix.."_user` WHERE `user_id`=?", id);
   if stmt then
      for row in stmt:rows(true) do
         return row;
      end
   end
end

local function get_user_by_name_or_id(id)
   return get_user(id) or get_user_from_id(tonumber(id))
end

local function get_friends(username)
   local stmt, err = getsql("SELECT * FROM `"..params.prefix.."_friend` WHERE `user_id`=?", get_user_by_name_or_id(username).user_id);
   if stmt then
      local friends = {}; i = 1;
      for row in stmt:rows(true) do
         local friend = get_user_from_id(row.friend_user_id);
         if friend and friend.view_id ~= params.exclude_view then
            friends[i] = friend
            i = i + 1
         end
      end
      return friends
   end
end

local char = string.char

local function tail(n, k)
   local u, r=''
   for i=1,k do
      n,r = math.floor(n/0x40), n%0x40
      u = char(r+0x80) .. u
   end
   return u, n
end

local function to_utf8(a)
   local n, r, u = tonumber(a)
   if n<0x80 then                        -- 1 byte
      return char(n)
   elseif n<0x800 then                   -- 2 byte
      u, n = tail(n, 1)
      return char(n+0xc0) .. u
   elseif n<0x10000 then                 -- 3 byte
      u, n = tail(n, 2)
      return char(n+0xe0) .. u
   elseif n<0x200000 then                -- 4 byte
      u, n = tail(n, 3)
      return char(n+0xf0) .. u
   elseif n<0x4000000 then               -- 5 byte
      u, n = tail(n, 4)
      return char(n+0xf8) .. u
   else                                  -- 6 byte
      u, n = tail(n, 5)
      return char(n+0xfc) .. u
   end
end

function unescape_entities(str)
   str = string.gsub(str, '&#(%d+);', to_utf8)
   return str
end

function new_default_provider(host)
   local provider = { name = "phpfox" };
   log("debug", "initializing default authentication provider for host '%s'", host);

   function provider.test_password(username, password)
      local user = get_user_by_name_or_id(username)
      local user_password = string.sub(user.password, 1, 32)
      local user_salt = string.sub(user.password_salt, 1, 3)

      if not password then
         return false
      end

      -- First auth mechanism: simple passwork check
      if (md5(md5(password, true)..md5(user_salt, true), true) == user_password) then
         return true
      else
         -- Second auth mechanism: check user_hash token
         local seed = string.sub(password, -10, -1)
         local password_hash = md5(md5(user_password, true) .. md5(user_salt, true), true) .. (params.custom_salt or "")
         local token = sha1(seed .. md5(password_hash, true) .. seed, true) .. seed
         return token == password
      end
   end

   function provider.get_password(username)
      return nil, "Not supported"
   end

   function provider.set_password(username, password)
      return nil, "Not supported"
   end

   function provider.user_exists(username)
      return get_user_by_name_or_id(username) and true;
   end

   function provider.create_user(username, password)
      return nil, "Not supported"
   end

   function provider.delete_user(username)
      return nil, "Not supported"
   end

   function provider.get_sasl_handler()
      local sasl = {};
      function sasl:clean_clone() return provider.get_sasl_handler(); end
      function sasl:mechanisms() return { PLAIN = true; }; end
      function sasl:select(mechanism)
         if not self.selected and mechanism == "PLAIN" then
            self.selected = mechanism;
            return true;
         end
      end

      function sasl:process(message)
         if not message then return "failure", "malformed-request"; end
         local username, password = message:match("^[^%z]*%z([^%z]+)%z([^%z]+)");

         local user = get_user_by_name_or_id(username)
         if not user then return "", nil; end

         if provider.test_password(username, password) then
            self.username = username

            -- populate the Roster
            roster = {}
            for i, friend in pairs(get_friends(username)) do
               roster[friend.user_name ..  '@' .. host] = {
                  jid = friend.user_name ..  '@' .. host,
                  subscription = "both",
                  name = unescape_entities(friend.full_name),
                  groups = {}
               }
            end
            rostermanager.save_roster(username, module.host, roster);
            return "success";
         end
         return "failure", "not-authorized", "Unable to authorize you with the authentication credentials you've sent.";
      end
      return sasl;
   end

   return provider;
end

module:add_item("auth-provider", new_default_provider(module.host));

-- Add an API path to get some kind of HMAC token

-- function GET_token(event)
--    local request, response = event.request, event.response;
--    log("debug", request.headers.cookie)

--    local headers = response.headers;
--    headers.content_type = "application/json";

--    local cookie = request.headers.cookie .. ";"
--    local user_id = string.match(cookie, "user_id=([^;]+);")
--    local user_hash = string.match(cookie, "user_hash=([^;]+);")
--    log("debug", user_id)

--    if not user_hash or not user_id then
--       response:send([[{"error": "unauthorized"}]])
--       return 403
--    end

--    local user = get_user_from_id(row.friend_user_id);
--    if not user then
--       response:send([[{"error": "unauthorized"}]])
--       return 403
--    end
--    local password = string.sub(user.password, 1, 32)
--    local salt = string.sub(user.password_salt, 1, 3)

--    local password_hash = md5(md5(password, true) .. md5(salt, true), true) .. params.custom_salt

--   local session_file = io.open(params.session_path .. "sess_" .. session)
--   if not session_file then
 --     response:send([[{"error": "unauthorized"}]])
 --     return 403
 --  end
 --  session_content = session_file:read("*all")
 --  session_file:close()

--   response:send([[{"token": "123456789"}]])

--   return 200;
--end

--	module:depends("http");
--	module:provides("http", {
--		default_path = "/token";
--		route = {
--			["GET"] = GET_token;
--			["GET /"] = GET_token;
--		};
--	});

