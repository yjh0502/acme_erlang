-module(acme_server).

-behaviour(gen_server).

%% API functions
-export([start_link/2]).
-export([new_reg/1, new_authz/1, new_cert/1, call/2]).
-export([get_key/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
    key,
    directory,
    nonce
}).

start_link(Key, DirectoryUrl) ->
    {Nonce, Resp} = parse_resp(hackney:get(DirectoryUrl, [], <<>>, [])),
    Dir = jsx:decode(Resp, [{labels, attempt_atom}, return_maps]),
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Key, Dir, Nonce], []).

new_reg(Body) ->
    gen_server:call(?MODULE, {'new-reg', Body}).

new_authz(Body) ->
    gen_server:call(?MODULE, {'new-authz', Body}).

call(Url, Body) ->
    gen_server:call(?MODULE, {url, Url, Body}).

new_cert(Body) ->
    gen_server:call(?MODULE, {'new-cert', Body}).

revoke_cert() ->
    gen_server:call(?MODULE, 'revoke-cert').

get_key() ->
    gen_server:call(?MODULE, get_key).

init([Key, Dir, Nonce]) ->
    {ok, #state{
        key=Key,
        directory=Dir,
        nonce=Nonce
    }}.

handle_call(get_key, _From, S=#state{key=Key}) ->
    {reply, Key, S};

handle_call({Method, Body}, _From, S = #state{key=Key, directory=Dir, nonce=Nonce}) ->
    Url = maps:get(Method, Dir),
    {NextNonce, Resp} = post(Url, Key, Nonce, Body),
    {reply, Resp, S#state{nonce=NextNonce}};

handle_call({url, Url, Body}, _From, S = #state{key=Key, nonce=Nonce}) ->
    {NextNonce, Resp} = post(Url, Key, Nonce, Body),
    {reply, Resp, S#state{nonce=NextNonce}};

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

post(Url, Key, Nonce, Payload) ->
    Jws = jws:sign(Key, Nonce, Payload),
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    parse_resp(hackney:post(Url, Headers, Jws, [])).

parse_resp({ok, _StatusCode, RespHeaders, Ref}) ->
    io:format("~p ~p~n", [_StatusCode, RespHeaders]),
    {_, Nonce} = lists:keyfind(<<"Replay-Nonce">>, 1, RespHeaders),
    {ok, Body} = hackney:body(Ref),
    {Nonce, Body}.
