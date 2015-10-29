-module(acme).

new_reg(Key, Nonce) ->
    Payload = jsx:encode(#{
        resource => 'new-reg',
        contact => [
            <<"mailto:sh.kang@5minlab.com">>,
            <<"tel:+821076280502">>
        ],
        agreement => <<"http://127.0.0.1:4001/terms/v1">>
    }),
    Url = <<"http://localhost:4000/acme/new-reg">>,
    call(Url, Key, Nonce, Payload).

new_authz(Key, Nonce) ->
    Payload = jsx:encode(#{
        resource => 'new-authz',
        identifier => #{
            type => dns,
            value => <<"testbed.5ml.io">>
        },
        agreement => <<"http://127.0.0.1:4001/terms/v1">>,
        authorizations => <<"http://127.0.0.1:4000/acme/reg/1/authz">>,
        certificates => <<"http://127.0.0.1:4000/acme/reg/1/certs">>
    }),
    Url = <<"http://localhost:4000/acme/new-authz">>,
    call(Url, Key, Nonce, Payload).

iv_http(Key, Nonce, Url) ->
    Payload = jsx:encode(#{
        resource => challenge,
        type => simpleHttp,
        tls => false
    }),
    call(Url, Key, Nonce, Payload).

generate_token(Token) ->
    Path = <<"www/.well-known/acme-challenge/", Token/binary>>,
    Jwk = jwk:build_jws(jwk:key(), <<>>, jsx:encode(#{
        type => <<"simpleHttp">>,
        token => Token,
        tls => false
    })),
    file:write_file(Path, Jwk).

call(Url, Key, Nonce, Payload) ->
    Jws = jws:sign(Key, Nonce, Payload),
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    case hackney:post(Url, Headers, Jws, []) of
        {ok, StatusCode, RespHeaders, Ref} ->
            {StatusCode, RespHeaders, hackney:body(Ref)}
    end.

