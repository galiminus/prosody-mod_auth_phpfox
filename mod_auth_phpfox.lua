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

local prosody = _G.prosody;

local connection;
local params = module:get_option("auth_sql", module:get_option("phpfox"));

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

function new_default_provider(host)
   local provider = { name = "phpfox" };
   log("debug", "initializing default authentication provider for host '%s'", host);

   function provider.test_password(username, password)
      local user = get_user(username)

      return password and (md5(md5(password, true)..md5(user.password_salt, true), true) == user.password)
   end

   function provider.get_password(username)
      return nil, "Not supported"
   end

   function provider.set_password(username, password)
      return nil, "Not supported"
   end

   function provider.user_exists(username)
      log("debug", "test user %s", username);
      return get_user(username) and true;
   end

   function provider.create_user(username, password)
      return nil, "Not supported"
   end

   function provider.delete_user(username)
      return nil, "Not supported"
   end

   function provider.get_sasl_handler()
      local profile = {
         plain = function(sasl, username, realm)
            local user = get_user(username)
            if not user then return "", nil; end
            return user.password, true;
         end
      };
      return new_sasl(module.host, profile);
   end

   return provider;
end

module:add_item("auth-provider", new_default_provider(module.host));
