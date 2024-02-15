# Pghttp: Backend-free Web Applications

Pghttp lets you make backend-free web applications by framing Postgres binary protocol into HTTP.

Pghttp web applications pass requests to and interpret responses from Postgres in its binary protocol format.
The proxy translates the Postgres protocol traffic from HTTP that browsers speak to TCP that Postgres expects.

The effect is that the client side application securely speaks to the database in good old-fashioned client-server
style, yet modernized to benefit from HTTP/2, HTTP/3, and QUIC and Internet web architecture.

Pghttp lets us build fast, low-latency, true client-only applications, the true inverse of server-rendered apps.
It removes the need for backend services on the fast path. Most backends nowadays do protocol conversion, anyway. 

## Pghttp Proxy for Nginx

The proxy lives on Nginx as a module. This is the right place for it to live, as it is an HTTP concern, and does
what Nginx is good at: HTTP processing and reverse proxying protocols. One can think of it as "FCGI for databases,"
only much faster and more capable.

## Requirements

This proxy runs on Nginx. It depends on [OpenResty](https://openresty.org), or [nginx-lua-module](https://github.com/openresty/lua-nginx-module).

In addition, the API mode requires tooling to compile API files. The tooling is presently hosted in the separate repository
in the pghttp GitHub organization.

## Installation

Copy the `pgproxy` folder into your Nginx configuration, and then reference it from `nginx.conf`.

Define Postgres users for authenticated and non-authenticated requests and inject them into nginx environment.

Set up Postgres to accept MD5 connections for those user accounts.

## Configuration

An example location in an Nginx site might look like this:

    location = /_pq/ {
      # API calls are always issued with POST method
      if ($request_method !~ ^(OPTIONS|POST)$) {
        add_header Allow "OPTIONS, POST" always;
        return 405;
      }

      # Rate-limit as we're not authenticating requests in this location
      limit_req zone=api burst=5 delay=5;

      # Production should only allow API calls pre-defined in the api_messages.cdb file
      # Already defaults to false, make it explicit to avoid log warnings
      set $pg_allow_ad_hoc_query 'off';

      # Read compiled API calls
      set $pg_api ${deployment_prefix}/proxy.d/api_messages.cdb;

      # This is an unauthenticated API, use low-privileged account
      set_by_lua_block $dummy {
        ngx.ctx.pg_vars = {
          pg_user_name = os.getenv("PG_ANON_USER"),
          pg_user_password = os.getenv("PG_ANON_PASSWORD")
        }
        return nil
      }
      # Pgproxy works in the nginx content phase
      content_by_lua_file ${deployment_prefix}/pgproxy/proxy.lua;
    }

## Configuration Parameters

### Environment variables

| Name | Description |
| ---- | ----------- |
| PG_USER | Username for authenticated apis. This user should be added to `dbname_db_access` role. |
| PG_PASSWORD | Password for `PG_USER` |
| PG_ANON_USER | Username for non-authenticated apis. This user should be added to `dbname_db_public` role. |
| PG_ANON_PASSWORD | Password for the anon user. |

`nginx.conf` must contain references to these variables in order to be accessible from nginx-lua-module:

    env PG_USER;
    env PG_PASSWORD;
    env PG_ANON_USER;
    env PG_ANON_PASSWORD;

### Nginx variables


| Name | Default | Description |
| ---- | ----------- | ---- |
| pg_database |  | Name of the database to connect to. Most apis will have this fixed. During development, one can pass the database name in a header. |
| pg_database_header | `off` | Set to `on` to allow setting the database name through HTTP header `pg_database`. |
| pg_allow_ad_hoc_query | `off` | Set to `on` to allow text mode ad-hoc queries to be passed to the database. If `off`, only queries predefined in the API table are allowed. Never enable on a production site. |
| pg_allow_copy_in | `off` | Allow copy_in protocol mode for binary bulk import. |
| pg_user_name | | Username to connect to the database with. Usually set from an env variable. |
| pg_user_password || Password to go with the username. |
| pg_application_name | String `pghttp:` + process pid of nginx worker | Application name to pass to Postgres. Useful to show in `pg_stat_statements` |
| pg_development_mode | `off` | Set to `on` to signal development mode configuration. Presently unused. |
| pg_host | `127.0.0.1` | Database host IP address or name for connecting to the database |
| pg_port | `5432` | Port the database is exposed on. |


### HTTP Headers

| Name | Default | Description |
| ---- | ----------- | ---- |
| pg-database |  | Name of the database to connect to. Most apis will have this fixed. During development, one can pass the database name in a header. |


## Limitations

Requires MD5 connections to Postgres. Modern Postgres defaults to SCRAM, so this will have to be a manual change in pg_hba.conf.

True superuser connections are not possible, as Postgres expects superuser TCP connection to stay active. Pghttp connects through nginx 
connection pool, and returns the connection to the pool after each request. We'd have to find the way to keep the connection open end-to-end
from the browser to the database. 

Possibly a web socket would be a solution, need to explore whether the connection would be held end-to-end.

The workaround is to set up a location in pghttp using `dbname_db_owner` user. It's not exactly the same as the database cluster superuser,
but is likely enough for most uses.