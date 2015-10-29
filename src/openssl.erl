-module(openssl).

-export([gen_rsa/0, gen_csr/2]).

-define(PORT_OPT, [binary, stream, use_stdio, eof]).

gen_rsa() ->
    list_to_binary(os:cmd("openssl genrsa 2> /dev/null")).

gen_csr(Key, DomainName) ->
    Cmd = iolist_to_binary(["openssl req -new -sha256 -key /proc/self/fd/0 -subj '/CN=", DomainName, "' -out /proc/self/fd/1"]),
    Port = open_port({spawn, Cmd}, ?PORT_OPT),
    Port ! {self(), {command, Key}},
    do_read(Port).

do_read(Port) ->
    do_read(Port, []).
do_read(Port, Acc) ->
    receive
        {Port,{data,Data}} ->
            do_read(Port, [Data | Acc]);
        {Port,eof} ->
            port_close(Port),
            {ok, iolist_to_binary(lists:reverse(Acc))}
    after 5000 ->
        port_close(Port),
        {error, timeout}
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

gen_rsa_test() ->
    Rsa = gen_rsa(),
    ?assertMatch([_Key], public_key:pem_decode(Rsa)).

gen_csr_test() ->
    Rsa = gen_rsa(),
    {ok, Csr} = gen_csr(Rsa, <<"example.com">>),
    ?assertMatch([_Csr], public_key:pem_decode(Csr)).

-endif.
