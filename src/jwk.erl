-module(jwk).

-export([generate_key/1, sign/2, verify/3]).
-export([from_pem/1, to_pem/1]).

-include_lib("public_key/include/public_key.hrl").

sign(BinKey, Data) when is_binary(BinKey) ->
    Key = jsx:decode(BinKey, [{labels, attempt_atom}, return_maps]),
    sign(Key, Data);

sign(#{kty := <<"RSA">>, n := N, e := E, d := D, p := P, q := Q, dp := Dp, dq := Dq, qi := Qi}, Data) ->
    Key = [
        from_base64(E),
        from_base64(N), 
        from_base64(D),
        from_base64(P), from_base64(Q),
        from_base64(Dp), from_base64(Dq),
        from_base64(Qi)
    ],
    base64url:encode(crypto:sign(rsa, sha256, Data, Key));

sign(Token = #{kty := <<"EC">>}, Data) ->
    Sk = ecdsa_privkey(Token),
    {HashAlg, Curve, SigLen} = ecdsa_curve_info(Token),

    Signature = crypto:sign(ecdsa, HashAlg, Data, [Sk, Curve]),
    {'ECDSA-Sig-Value', R, S} = public_key:der_decode('ECDSA-Sig-Value', Signature),
    SigBin = <<R:SigLen/integer, S:SigLen/integer>>,
    base64url:encode(SigBin).

verify(#{kty := <<"RSA">>, n := N, e := E}, Data, Signature) ->
    crypto:verify(rsa, sha256, Data, base64url:decode(Signature), [from_base64(E), from_base64(N)]);

verify(Token = #{kty := <<"EC">>}, Data, Signature) ->
    Pk = ecdsa_pubkey(Token),
    {HashAlg, Curve, SigLen} = ecdsa_curve_info(Token),

    <<R:SigLen/integer, S:SigLen/integer>> = base64url:decode(Signature),
    DerSignature = public_key:der_encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value', R, S}),
    crypto:verify(ecdsa, HashAlg, Data, DerSignature, [Pk, Curve]).


from_base64(Bin) ->
    from_bin(base64url:decode(Bin)).

from_bin(Bin) ->
    BitSize = byte_size(Bin) * 8,
    <<Integer:BitSize/integer>> = Bin,
    Integer.


ecdsa_pubkey(#{x := X, y := Y}) ->
    BinX = base64url:decode(X),
    BinY = base64url:decode(Y),
    <<4:8, BinX/binary, BinY/binary>>.

ecdsa_privkey(#{d := D}) ->
    base64url:decode(D).

ecdsa_curve_info(#{crv := <<"P-256">>}) ->
    {sha256, secp256r1, 256};
ecdsa_curve_info(#{crv := <<"P-384">>}) ->
    {sha384, secp384r1, 384};
ecdsa_curve_info(#{crv := <<"P-521">>}) ->
    {sha512, secp521r1, 528}.

to_base64(Integer) ->
    base64url:encode(to_bin(Integer)).
    
to_bin(Integer) ->
    BitSize = byte_size(integer_to_binary(Integer, 16)) * 4,
    ByteSize = (BitSize + 7) div 8,
    <<Integer:(ByteSize*8)/integer>>.

generate_key(rsa) ->
    from_pem(openssl:gen_rsa());

generate_key(ecdsa) ->
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

from_pem(Pem) ->
    [Key] = public_key:pem_decode(Pem),
    {
        'RSAPrivateKey','two-prime',
        N, E, D, P, Q, Dp, Dq, Qi, asn1_NOVALUE
    } = public_key:pem_entry_decode(Key),
    jsx:encode(#{
        kty => 'RSA',
        use => sig,
        n => to_base64(N),
        e => to_base64(E),
        d => to_base64(D), p => to_base64(P), q => to_base64(Q),
        dp => to_base64(Dp), dq => to_base64(Dq), qi => to_base64(Qi)
    }).

to_pem(Key) ->
    case jsx:decode(Key, [{labels, attempt_atom}, return_maps]) of
        #{kty := <<"RSA">>,
            n := N, e := E, d := D, p := P, q := Q,
            dp := Dp, dq := Dq, qi := Qi} ->
            TupleKey = {
                'RSAPrivateKey','two-prime',
                from_base64(N), from_base64(E),
                from_base64(D), from_base64(P), from_base64(Q),
                from_base64(Dp), from_base64(Dq), from_base64(Qi),
                asn1_NOVALUE
            },
            PemKey = public_key:pem_entry_encode('RSAPrivateKey', TupleKey),
            public_key:pem_encode([PemKey])
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

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

sign_verify_test() ->
    BinToken = <<"{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\",\"use\":\"enc\",\"kid\":\"1\"}">>,
    Token = jsx:decode(BinToken, [{labels, attempt_atom}, return_maps]),
    Pk = ecdsa_pubkey(Token),
    Sk = ecdsa_privkey(Token),

    Data = <<"hello">>,
    Signature = crypto:sign(ecdsa, sha256, Data, [Sk, secp256r1]),
    ?assertEqual(true, crypto:verify(ecdsa, sha256, Data, Signature, [Pk, secp256r1])).

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

ec_sig_encode_test() ->
    % from rfc7515, appendix-A.4
    R = <<1,220,12,129,231,171,194,209,232,135,233,117,247,105,122,210,26,125,192,1,217,21,82,91,45,240,255,83,19,34,239,71,48,157,147,152,105,18,53,108,163,214,68,231,62,153,150,106,194,164,246,72,143,138,24,50,129,223,133,206,209,172,63,237,119,109>>,
    S = <<0,111,6,105,44,5,41,208,128,61,152,40,92,61,152,4,150,66,60,69,247,196,170,81,193,199,78,59,194,169,16,124,9,143,42,142,131,48,206,238,34,175,83,203,220,159,3,107,155,22,27,73,111,68,68,21,238,144,229,232,148,188,222,59,242,103>>,
    Sig = <<"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn">>,
    ?assertEqual(Sig, base64url:encode(<<R/binary, S/binary>>)).

pem_test() ->
    Key = generate_key(rsa),
    PemKey = to_pem(Key),
    ?assertEqual(Key, from_pem(PemKey)).

generate_key_test() ->
    generate_key(rsa),
    generate_key(ecdsa),
    ok.

-endif.
