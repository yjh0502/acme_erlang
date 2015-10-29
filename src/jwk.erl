-module(jwk).
-compile(export_all).

-include_lib("public_key/include/public_key.hrl").

% -define(KEY, <<"{\"crv\":\"P-521\",\"d\":\"AKO3eV2pdeEc6okY73F_2LTPXVITE3QQ8BZ6HbZNlQtXDSTD4U17p1rzBcN1XCEGid58HzM0bfbkB5wQLRI1g9dK\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"AN-CDxr0UBzgBjOaYt0Hr3GZuLGfa7RYAQO6OkeOJ7MJ4jAMkTh7_gNrQ9EffEyX7DuaZs740xJuiw-AyzBVihSD\",\"y\":\"ARdKxDsBiGgYEoEmCIR751I3jtuHq64QTtwqv04cbQjC_wb7IlHYm7T-l-DQPkDJUwzzB8LAOXBMJiBHcHA9R-yf\"}">>).
-define(KEY, <<"{\"d\":\"HXrpwTB_EvnrUrHIpmt3nbQj5WKCFOiauEzQdoIbSCsQRhRTaMUdOLmCVXa8Dgv-cICl0o6B5v-uxfgTf3UHZQkQDGv0zGQK0Lnt2-CwR802vdEE1zDE4BffOy6B3DQnDvSOMKQKzgdRSo5nwj-tWPtmS-KFnlcWAXs2kCS-00s-c5HqnkWM9BmR9Yza7fjYigS6RXqenPsJ1KTxKNiHTyvA2vm9p6sZvppW0KCnQTA0HDpJ0omRW8cadPT2s4l3MJrOt2Bojpq5HAMj1OFplBjSP5E9bwRAUgLoATOr-xqcT0FrzDbRjubUthkwy8BW6nlDwRR9-ZzThyFl5eY6XQ\",\"dp\":\"Q9tq8cG3Z3ZwImRewKaa3mCax_qZu23Oiv9xXuFM79IwV9Ab2VU-unj_IcijnlnaYA9ocputsFEPOfa0r3SYwvqWYljE0enyyWa1gLDwdEhB7YXdGbNzOdOzfRAIzE5J65uxTKMLw52j8bIAQZoN8osBFuJR53HOzVElmJCtRTM\",\"dq\":\"DQ_m6YmswSQh-mzbajuKL4Y7TytSKKMqEJzdW_HDiFRv4NipM4jwUGYRIhIcf0wJSW29SBuSBERCta_cikgryr8cvdUB8AKRHxHy1YMsWIzEnNTrYHNsqXbEqACtYfU7Q8bRDyu2Lfqy8VSV1duEDKvEXkUOIv3wfMfbZvl5Ea0\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"xHw30jzFpG99HPQVxTdt0bQtIccS9tPcgxlaCWMpOF_Ryr-aSNvjuNcF1MIM_FSS2V3dJQ5ba9nuZDQ2PoycKIWjgtMsgKI6Y9Y0EIUys9XJJT_hY3f--yak4TGs6l2MvzB7BPqLVwmW0PJ_A8Kmy8SEjOvqDJEtz1jA8_rezoQ_FhEzaz0KS7syx_dhhFxEeT4ZNHMrED5ZuuFu3i4qpePti8R2T7AVfrMV4rDGv59CmMjCvEDv42PRnKHnxVWhKhani9xkXeO0Fv6Dh4W6zvDnSu2vfOWiUNWbN96gio8QLYXV4OQ3jJ1SkgCc7jwFPLszq_ImhG9Vj3fqkKNfPQ\",\"p\":\"_yD7oED9cnqRQu8GST8o1AGaaFLbW5A8SP3YtCd5fQNdmNHG1P_W36vILGiWnBSDU0EkWWnC_gc_l8EfPZHiTDaYT__eygnZqKMuF5BIN3dyvgK2IqOIaX3tLuMNCCq9sGTDN653cK474bc2je9HuQyFrLgQATq8HvVWGkNwGZ8\",\"q\":\"xSf5AoLJzkp45ht3KVPdRuSxMgjN4eQYRyjMSB02e8_m11me2NwGrqi2i5IEF510eLDNDOc-mte6x27bN9Ew30Woy92N6lU0GS37fMH3flsZ6xnWGhtsLuXUTEDvw8e1EEcJMmV9NfC5msxrr2x6pU9rixv4dL5J-h_ZQQZAkaM\",\"qi\":\"1jMK_hfvQv2d6VsTRrz2TkeCq_QqP38OLOaovAxSBB3MCABBHLDiNVQWNpKtu1YR7YVngZtFXa9dXoru0fXhYGQGQDiqXWAt569ZCaFoneNq2lBMe2FDAlBNKJq1XYkltLyGhjlL3rFjy1XkPAUujaLp1qPybDlqEB7ewo-_sWw\",\"use\":\"sig\"}">>).

key() ->
    ?KEY.

read_csr_test() ->
    {ok, File} = file:read_file("key/out.csr"),
    [Csr] = public_key:pem_decode(File),
    public_key:pem_entry_decode(Csr).

new_reg(Nonce) ->
    Payload = jsx:encode(#{
        resource => 'new-reg',
        contact => [
            <<"mailto:sh.kang@5minlab.com">>,
            <<"tel:+821076280502">>
        ],
        agreement => <<"http://127.0.0.1:4001/terms/v1">>
    }),
    Url = <<"http://localhost:4000/acme/new-reg">>,
    call(Url, key(), Nonce, Payload).

new_authz(Nonce) ->
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
    call(Url, key(), Nonce, Payload).

iv_http(Url, Nonce) ->
    Payload = jsx:encode(#{
        resource => challenge,
        type => simpleHttp,
        tls => false
    }),
    call(Url, key(), Nonce, Payload).

generate_token(Token) ->
    Path = <<"www/.well-known/acme-challenge/", Token/binary>>,
    Jwk = jwk:build_jws(jwk:key(), <<>>, jsx:encode(#{
        type => <<"simpleHttp">>,
        token => Token,
        tls => false
    })),
    file:write_file(Path, Jwk).

call(Url, Key, Nonce, Payload) ->
    Jws = build_jws(Key, Nonce, Payload),
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    case hackney:post(Url, Headers, Jws, []) of
        {ok, StatusCode, RespHeaders, Ref} ->
            {StatusCode, RespHeaders, hackney:body(Ref)}
    end.


token_to_pubkey(#{x := X, y := Y}) ->
    BinX = base64url:decode(X),
    BinY = base64url:decode(Y),
    <<4:8, BinX/binary, BinY/binary>>.

token_to_privkey(#{d := D}) ->
    base64url:decode(D).

sign(Token = #{kty := <<"EC">>}, Data) ->
    Sk = token_to_privkey(Token),
    {HashAlg, Curve, SigLen} = ecdsa_curve_info(Token),

    Signature = crypto:sign(ecdsa, HashAlg, Data, [Sk, Curve]),
    {'ECDSA-Sig-Value', R, S} = public_key:der_decode('ECDSA-Sig-Value', Signature),
    SigBin = <<R:SigLen/integer, S:SigLen/integer>>,
    base64url:encode(SigBin);

sign(#{kty := <<"RSA">>, n := N, e := E, d := D, p := P, q := Q, dp := Dp, dq := Dq, qi := Qi}, Data) ->
    Key = [
        from_base64(E),
        from_base64(N), 
        from_base64(D),
        from_base64(P), from_base64(Q),
        from_base64(Dp), from_base64(Dq),
        from_base64(Qi)
    ],
    base64url:encode(crypto:sign(rsa, sha256, Data, Key)).

verify(Token = #{kty := <<"EC">>}, Data, Signature) ->
    Pk = token_to_pubkey(Token),
    {HashAlg, Curve, SigLen} = ecdsa_curve_info(Token),

    <<R:SigLen/integer, S:SigLen/integer>> = base64url:decode(Signature),
    DerSignature = public_key:der_encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value', R, S}),
    crypto:verify(ecdsa, HashAlg, Data, DerSignature, [Pk, Curve]);

verify(#{kty := <<"RSA">>, n := N, e := E}, Data, Signature) ->
    crypto:verify(rsa, sha256, Data, base64url:decode(Signature), [from_base64(E), from_base64(N)]).

ecdsa_curve_info(#{crv := <<"P-256">>}) ->
    {sha256, secp256r1, 256};
ecdsa_curve_info(#{crv := <<"P-384">>}) ->
    {sha384, secp384r1, 384};
ecdsa_curve_info(#{crv := <<"P-521">>}) ->
    {sha512, secp521r1, 528}.

read_rsa_key(Filename) ->
    {ok, File} = file:read_file(Filename),
    [Key] = public_key:pem_decode(File),
    {'RSAPrivateKey','two-prime', N, E, D, P, Q, Dp, Dq, Qi, asn1_NOVALUE} = public_key:pem_entry_decode(Key),
    jsx:encode(#{
        kty => 'RSA',
        use => sig,
        n => to_base64(N),
        e => to_base64(E),
        d => to_base64(D), p => to_base64(P), q => to_base64(Q),
        dp => to_base64(Dp), dq => to_base64(Dq), qi => to_base64(Qi)
    }).

to_base64(Integer) ->
    base64url:encode(to_bin(Integer)).
    
to_bin(Integer) ->
    BitSize = byte_size(integer_to_binary(Integer, 16)) * 4,
    ByteSize = (BitSize + 7) div 8,
    <<Integer:(ByteSize*8)/integer>>.

from_base64(Bin) ->
    from_bin(base64url:decode(Bin)).

from_bin(Bin) ->
    BitSize = byte_size(Bin) * 8,
    <<Integer:BitSize/integer>> = Bin,
    Integer.

generate_key() ->
    {Pk,Sk} = crypto:generate_key(ecdh, secp521r1),
    <<4:8, X:66/binary, Y:66/binary>> = Pk,
    SkLen = byte_size(Sk),
    PadSize = (66 - SkLen),
    PaddedSk = <<0:(PadSize*8)/integer, Sk/binary>>,
    jsx:encode(#{
        kty => 'EC',
        use => sig,
        crv => 'P-521',
        x => base64url:encode(X),
        y => base64url:encode(Y),
        d => base64url:encode(PaddedSk)
    }).

build_jws(BinKey, Nonce, Payload) ->
    Key = jsx:decode(BinKey, [{labels, attempt_atom}, return_maps]),
    ProtectedHeader = case Key of
        #{crv := <<"P-521">>} ->
            jsx:encode(#{
                alg => 'ES512',
                nonce => Nonce,
                jwk => maps:with([kty, kid, use, crv, x, y], Key)
            });
        #{kty := <<"RSA">>} ->
            jsx:encode(#{
                alg => 'RS256',
                nonce => Nonce,
                jwk => maps:with([kty, kid, use, n, e], Key)
            });
        _ ->
            throw(not_supported_key)
    end,
    ProtectedBase64 = base64url:encode(ProtectedHeader),
    PayloadBase64 = base64url:encode(Payload),
    SignInput = <<ProtectedBase64/binary, ".", PayloadBase64/binary>>,
    Signature = sign(Key, SignInput),
    jsx:encode(#{
        protected => ProtectedBase64,
        payload => PayloadBase64,
        signature => Signature
    }).

verify_jws(Bin) ->
    #{
        protected := Protected,
        payload := Payload,
        signature := Signature
    } = jsx:decode(Bin, [{labels, attempt_atom}, return_maps]),
    #{jwk := Key} = jsx:decode(base64url:decode(Protected), [{labels, attempt_atom}, return_maps]),
    SignInput = <<Protected/binary, ".", Payload/binary>>,
    verify(Key, SignInput, Signature).

-include_lib("eunit/include/eunit.hrl").

sign_verify_test() ->
    BinToken = <<"{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\",\"use\":\"enc\",\"kid\":\"1\"}">>,
    Token = jsx:decode(BinToken, [{labels, attempt_atom}, return_maps]),
    Pk = token_to_pubkey(Token),
    Sk = token_to_privkey(Token),

    Data = <<"hello">>,
    Signature = crypto:sign(ecdsa, sha256, Data, [Sk, secp256r1]),
    ?assertEqual(true, crypto:verify(ecdsa, sha256, Data, Signature, [Pk, secp256r1])).

jws_test() ->
    BinToken = <<"{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}">>,
    Payload = <<"Payload">>,
    Jws = build_jws(BinToken, <<>>, Payload),
    verify_jws(Jws).

rsa_test() ->
    BinToken = <<"{\"d\":\"HXrpwTB_EvnrUrHIpmt3nbQj5WKCFOiauEzQdoIbSCsQRhRTaMUdOLmCVXa8Dgv-cICl0o6B5v-uxfgTf3UHZQkQDGv0zGQK0Lnt2-CwR802vdEE1zDE4BffOy6B3DQnDvSOMKQKzgdRSo5nwj-tWPtmS-KFnlcWAXs2kCS-00s-c5HqnkWM9BmR9Yza7fjYigS6RXqenPsJ1KTxKNiHTyvA2vm9p6sZvppW0KCnQTA0HDpJ0omRW8cadPT2s4l3MJrOt2Bojpq5HAMj1OFplBjSP5E9bwRAUgLoATOr-xqcT0FrzDbRjubUthkwy8BW6nlDwRR9-ZzThyFl5eY6XQ\",\"dp\":\"Q9tq8cG3Z3ZwImRewKaa3mCax_qZu23Oiv9xXuFM79IwV9Ab2VU-unj_IcijnlnaYA9ocputsFEPOfa0r3SYwvqWYljE0enyyWa1gLDwdEhB7YXdGbNzOdOzfRAIzE5J65uxTKMLw52j8bIAQZoN8osBFuJR53HOzVElmJCtRTM\",\"dq\":\"DQ_m6YmswSQh-mzbajuKL4Y7TytSKKMqEJzdW_HDiFRv4NipM4jwUGYRIhIcf0wJSW29SBuSBERCta_cikgryr8cvdUB8AKRHxHy1YMsWIzEnNTrYHNsqXbEqACtYfU7Q8bRDyu2Lfqy8VSV1duEDKvEXkUOIv3wfMfbZvl5Ea0\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"xHw30jzFpG99HPQVxTdt0bQtIccS9tPcgxlaCWMpOF_Ryr-aSNvjuNcF1MIM_FSS2V3dJQ5ba9nuZDQ2PoycKIWjgtMsgKI6Y9Y0EIUys9XJJT_hY3f--yak4TGs6l2MvzB7BPqLVwmW0PJ_A8Kmy8SEjOvqDJEtz1jA8_rezoQ_FhEzaz0KS7syx_dhhFxEeT4ZNHMrED5ZuuFu3i4qpePti8R2T7AVfrMV4rDGv59CmMjCvEDv42PRnKHnxVWhKhani9xkXeO0Fv6Dh4W6zvDnSu2vfOWiUNWbN96gio8QLYXV4OQ3jJ1SkgCc7jwFPLszq_ImhG9Vj3fqkKNfPQ\",\"p\":\"_yD7oED9cnqRQu8GST8o1AGaaFLbW5A8SP3YtCd5fQNdmNHG1P_W36vILGiWnBSDU0EkWWnC_gc_l8EfPZHiTDaYT__eygnZqKMuF5BIN3dyvgK2IqOIaX3tLuMNCCq9sGTDN653cK474bc2je9HuQyFrLgQATq8HvVWGkNwGZ8\",\"q\":\"xSf5AoLJzkp45ht3KVPdRuSxMgjN4eQYRyjMSB02e8_m11me2NwGrqi2i5IEF510eLDNDOc-mte6x27bN9Ew30Woy92N6lU0GS37fMH3flsZ6xnWGhtsLuXUTEDvw8e1EEcJMmV9NfC5msxrr2x6pU9rixv4dL5J-h_ZQQZAkaM\",\"qi\":\"1jMK_hfvQv2d6VsTRrz2TkeCq_QqP38OLOaovAxSBB3MCABBHLDiNVQWNpKtu1YR7YVngZtFXa9dXoru0fXhYGQGQDiqXWAt569ZCaFoneNq2lBMe2FDAlBNKJq1XYkltLyGhjlL3rFjy1XkPAUujaLp1qPybDlqEB7ewo-_sWw\",\"use\":\"sig\"}">>,
    Payload = <<"Payload">>,
    Jws = build_jws(BinToken, <<>>, Payload),
    verify_jws(Jws).

ecdsa_test() ->
    % from rfc7515, appendix-A.4
    BinToken = <<"{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}">>,
    Token = jsx:decode(BinToken, [{labels, attempt_atom}, return_maps]),
    ProtectedHeader = <<"{\"alg\":\"ES512\"}">>,
    Payload = <<"Payload">>,
    SignInput = <<(base64url:encode(ProtectedHeader))/binary, ".", (base64url:encode(Payload))/binary>>,

    ValidSignature = <<"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn">>,

    Signature = sign(Token, SignInput),
    ?assertEqual(true, verify(Token, SignInput, Signature)),
    ?assertEqual(true, verify(Token, SignInput, ValidSignature)).

signinput_test() ->
    % from rfc7515, appendix-A.4
    ProtectedHeader = <<"{\"alg\":\"ES512\"}">>,
    Payload = <<"Payload">>,
    SignInput = <<"eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA">>,
    ?assertEqual(SignInput, <<(base64url:encode(ProtectedHeader))/binary, ".", (base64url:encode(Payload))/binary>>).

base64_test() ->
    % from rfc7515, appendix-A.4
    Payload = <<"Payload">>,
    PayloadBase64 = <<"UGF5bG9hZA">>,
    ?assertEqual(PayloadBase64, base64url:encode(Payload)).

ec_key({PubKey, PrivateKey}) ->
    #'ECPrivateKey'{
        version = 1,
        privateKey = binary_to_list(PrivateKey),
        parameters = {namedCurve, secp256r1},
        publicKey = {0, PubKey}
    }.

ec_sig_encode_test() ->
    % from rfc7515, appendix-A.4
    R = <<1,220,12,129,231,171,194,209,232,135,233,117,247,105,122,210,26,125,192,1,217,21,82,91,45,240,255,83,19,34,239,71,48,157,147,152,105,18,53,108,163,214,68,231,62,153,150,106,194,164,246,72,143,138,24,50,129,223,133,206,209,172,63,237,119,109>>,
    S = <<0,111,6,105,44,5,41,208,128,61,152,40,92,61,152,4,150,66,60,69,247,196,170,81,193,199,78,59,194,169,16,124,9,143,42,142,131,48,206,238,34,175,83,203,220,159,3,107,155,22,27,73,111,68,68,21,238,144,229,232,148,188,222,59,242,103>>,
    Sig = <<"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn">>,
    ?assertEqual(Sig, base64url:encode(<<R/binary, S/binary>>)).

