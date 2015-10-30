-module(acme).

-compile([export_all]).

-define(MAIL, <<"mailto:root@example.com">>).
-define(TEL, <<"tel:+123456789012">>).
-define(DOMAIN, <<"example.com">>).

start() ->
    application:ensure_all_started(acme_erlang).

stop() ->
    application:stop(acme_erlang).

new_reg() ->
    Payload = jsx:encode(#{
        resource => 'new-reg',
        contact => [?MAIL, ?TEL],
        agreement => <<"http://127.0.0.1:4001/terms/v1">>
    }),
    acme_server:new_reg(Payload).

new_authz() ->
    Payload = jsx:encode(#{
        resource => 'new-authz',
        identifier => #{
            type => dns,
            value => ?DOMAIN
        },
        agreement => <<"http://127.0.0.1:4001/terms/v1">>
    }),
    Resp = acme_server:new_authz(Payload),
    #{challenges := Challenges} = jsx:decode(Resp, [{labels, attempt_atom}, return_maps]),
    lists:map(fun(Challenge) ->
        case Challenge of
            #{type := <<"simpleHttp">>, uri := Uri, token := Token} ->
                generate_token(Token),
                iv_http(Uri);
            _ ->
                unknown_challenge
        end
    end, Challenges).

new_cert() ->
    Domain = ?DOMAIN,
    Dir = <<"key/", Domain/binary>>,
    ok = case file:make_dir(Dir) of
        ok -> ok;
        {error, eexist} -> ok
    end,
    KeyPath = <<Dir/binary, "/.private">>,
    CertDerPath = <<Dir/binary, "/cert.der">>,
    CertPemPath = <<Dir/binary, "/cert.pem">>,
    PemKey = case file:read_file(KeyPath) of
        {ok, File} ->
            File;
        {error, _} ->
            Key = openssl:gen_rsa(),
            file:write_file(KeyPath, Key),
            Key
    end,
    {ok, Csr} = openssl:gen_csr(PemKey, Domain),
    Payload = jsx:encode(#{
        resource => 'new-cert',
        csr => base64url:encode(Csr)
    }),
    %% TODO: should handle HTTP/1.1 202 Accepted, Retry-After: 120
    DerCert = acme_server:new_cert(Payload),
    PemCert = public_key:pem_encode([{'Certificate', DerCert, not_encrypted}]),
    file:write_file(CertPemPath, PemCert),
    file:write_file(CertDerPath, DerCert).

generate_token(Token) ->
    Path = <<"www/", Token/binary>>,
    Key = acme_server:get_key(),
    Jwk = jws:sign(Key, jsx:encode(#{
        type => <<"simpleHttp">>,
        token => Token,
        tls => false
    })),
    file:write_file(Path, Jwk).

iv_http(Url) ->
    Payload = jsx:encode(#{
        resource => challenge,
        type => simpleHttp,
        tls => false
    }),
    acme_server:call(Url, Payload).

call(Url, Key, Nonce, Payload) ->
    Jws = jws:sign(Key, Nonce, Payload),
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    case hackney:post(Url, Headers, Jws, []) of
        {ok, StatusCode, RespHeaders, Ref} ->
            {StatusCode, RespHeaders, hackney:body(Ref)}
    end.

