%%%-------------------------------------------------------------------
%% @doc acme_erlang public API
%% @end
%%%-------------------------------------------------------------------

-module('acme_erlang_app').

-behaviour(application).

%% Application callbacks
-export([start/2
        ,stop/1]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/.well-known/acme-challenge/[...]", cowboy_static, {dir, "www"}}
        ]}
    ]),
    {ok, _} = cowboy:start_http(my_http_listener, 100, [{port, 5002}],
        [{env, [{dispatch, Dispatch}]}]
    ),
    'acme_erlang_sup':start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    cowboy:stop_listener(my_http_listener),
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
