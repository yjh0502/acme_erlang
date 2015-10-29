%%%-------------------------------------------------------------------
%% @doc acme_erlang top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module('acme_erlang_sup').

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
    Key = jwk:generate_key(rsa),
    DirUrl = <<"http://127.0.0.1:4000/directory">>,
    ChildSpecs = [
        #{
            id => acme_server,
            start => {acme_server, start_link, [Key, DirUrl]},
            restart => permanent,
            shutdown => brutal_kill,
            type => worker,
            modules => [acme_server]
        }
    ],
    {ok, { {one_for_all, 0, 1}, ChildSpecs} }.

%%====================================================================
%% Internal functions
%%====================================================================
