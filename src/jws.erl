-module(jws).

-export([sign/2, sign/3, verify/1]).

%% @doc sign without nonce
sign(BinKey, Payload) ->
    sign(BinKey, <<>>, Payload).

sign(BinKey, Nonce, Payload) ->
    Key = jsx:decode(BinKey, [{labels, attempt_atom}, return_maps]),
    KeyHeader = case Key of
        #{crv := <<"P-521">>} ->
            #{
                alg => 'ES512',
                jwk => maps:with([kty, kid, use, crv, x, y], Key)
            };
        #{kty := <<"RSA">>} ->
            #{
                alg => 'RS256',
                jwk => maps:with([kty, kid, use, n, e], Key)
            };
        _ ->
            throw(not_supported_key)
    end,
    ProtectedHeaderMap = case Nonce of
        <<>> ->
            KeyHeader;
        _ ->
            KeyHeader#{
                nonce => Nonce
            }
    end,

    ProtectedHeader = jsx:encode(ProtectedHeaderMap),
    ProtectedBase64 = base64url:encode(ProtectedHeader),
    PayloadBase64 = base64url:encode(Payload),
    SignInput = <<ProtectedBase64/binary, ".", PayloadBase64/binary>>,
    Signature = jwk:sign(Key, SignInput),
    jsx:encode(#{
        protected => ProtectedBase64,
        payload => PayloadBase64,
        signature => Signature
    }).

verify(Bin) ->
    #{
        protected := Protected,
        payload := Payload,
        signature := Signature
    } = jsx:decode(Bin, [{labels, attempt_atom}, return_maps]),
    #{jwk := Key} = jsx:decode(base64url:decode(Protected), [{labels, attempt_atom}, return_maps]),
    SignInput = <<Protected/binary, ".", Payload/binary>>,
    jwk:verify(Key, SignInput, Signature).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

rsa_test() ->
    BinToken = <<"{\"d\":\"HXrpwTB_EvnrUrHIpmt3nbQj5WKCFOiauEzQdoIbSCsQRhRTaMUdOLmCVXa8Dgv-cICl0o6B5v-uxfgTf3UHZQkQDGv0zGQK0Lnt2-CwR802vdEE1zDE4BffOy6B3DQnDvSOMKQKzgdRSo5nwj-tWPtmS-KFnlcWAXs2kCS-00s-c5HqnkWM9BmR9Yza7fjYigS6RXqenPsJ1KTxKNiHTyvA2vm9p6sZvppW0KCnQTA0HDpJ0omRW8cadPT2s4l3MJrOt2Bojpq5HAMj1OFplBjSP5E9bwRAUgLoATOr-xqcT0FrzDbRjubUthkwy8BW6nlDwRR9-ZzThyFl5eY6XQ\",\"dp\":\"Q9tq8cG3Z3ZwImRewKaa3mCax_qZu23Oiv9xXuFM79IwV9Ab2VU-unj_IcijnlnaYA9ocputsFEPOfa0r3SYwvqWYljE0enyyWa1gLDwdEhB7YXdGbNzOdOzfRAIzE5J65uxTKMLw52j8bIAQZoN8osBFuJR53HOzVElmJCtRTM\",\"dq\":\"DQ_m6YmswSQh-mzbajuKL4Y7TytSKKMqEJzdW_HDiFRv4NipM4jwUGYRIhIcf0wJSW29SBuSBERCta_cikgryr8cvdUB8AKRHxHy1YMsWIzEnNTrYHNsqXbEqACtYfU7Q8bRDyu2Lfqy8VSV1duEDKvEXkUOIv3wfMfbZvl5Ea0\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"xHw30jzFpG99HPQVxTdt0bQtIccS9tPcgxlaCWMpOF_Ryr-aSNvjuNcF1MIM_FSS2V3dJQ5ba9nuZDQ2PoycKIWjgtMsgKI6Y9Y0EIUys9XJJT_hY3f--yak4TGs6l2MvzB7BPqLVwmW0PJ_A8Kmy8SEjOvqDJEtz1jA8_rezoQ_FhEzaz0KS7syx_dhhFxEeT4ZNHMrED5ZuuFu3i4qpePti8R2T7AVfrMV4rDGv59CmMjCvEDv42PRnKHnxVWhKhani9xkXeO0Fv6Dh4W6zvDnSu2vfOWiUNWbN96gio8QLYXV4OQ3jJ1SkgCc7jwFPLszq_ImhG9Vj3fqkKNfPQ\",\"p\":\"_yD7oED9cnqRQu8GST8o1AGaaFLbW5A8SP3YtCd5fQNdmNHG1P_W36vILGiWnBSDU0EkWWnC_gc_l8EfPZHiTDaYT__eygnZqKMuF5BIN3dyvgK2IqOIaX3tLuMNCCq9sGTDN653cK474bc2je9HuQyFrLgQATq8HvVWGkNwGZ8\",\"q\":\"xSf5AoLJzkp45ht3KVPdRuSxMgjN4eQYRyjMSB02e8_m11me2NwGrqi2i5IEF510eLDNDOc-mte6x27bN9Ew30Woy92N6lU0GS37fMH3flsZ6xnWGhtsLuXUTEDvw8e1EEcJMmV9NfC5msxrr2x6pU9rixv4dL5J-h_ZQQZAkaM\",\"qi\":\"1jMK_hfvQv2d6VsTRrz2TkeCq_QqP38OLOaovAxSBB3MCABBHLDiNVQWNpKtu1YR7YVngZtFXa9dXoru0fXhYGQGQDiqXWAt569ZCaFoneNq2lBMe2FDAlBNKJq1XYkltLyGhjlL3rFjy1XkPAUujaLp1qPybDlqEB7ewo-_sWw\",\"use\":\"sig\"}">>,
    Payload = <<"Payload">>,
    Jws = sign(BinToken, <<>>, Payload),
    ?assertEqual(true, verify(Jws)).

ecdsa_test() ->
    BinToken = <<"{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}">>,
    Payload = <<"Payload">>,
    Jws = sign(BinToken, <<>>, Payload),
    ?assertEqual(true, verify(Jws)).

-endif.
