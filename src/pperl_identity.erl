%%%-------------------------------------------------------------------
%%% @doc Identity and certificate management for pperl.
%%%
%%% Handles generation, storage, and verification of peer identities
%%% using self-signed certificates for DTLS connections.
%%%
%%% Storage layout:
%%%   ~/.pperl/identity/cert.pem  - our certificate
%%%   ~/.pperl/identity/key.pem   - our private key
%%%   ~/.pperl/trusted/<name>.pem - trusted peer certificates
%%%-------------------------------------------------------------------
-module(pperl_identity).

-export([
    %% Identity management
    init/0,
    generate_identity/0,
    generate_identity/1,
    has_identity/0,
    get_identity/0,
    get_fingerprint/0,

    %% Peer trust management
    import_peer/2,
    import_peer/3,
    remove_peer/1,
    list_peers/0,
    get_peer_cert/1,
    get_peer_fingerprint/1,

    %% Peer connection info
    set_peer_address/2,
    get_peer_address/1,
    get_peer_info/1,
    format_peer_address/1,

    %% For DTLS configuration
    ssl_options/0,
    ssl_options/1,
    ssl_options/2,
    verify_peer_fun/0
]).

-define(PPERL_DIR, ".pperl").
-define(IDENTITY_DIR, "identity").
-define(TRUSTED_DIR, "trusted").
-define(CERT_FILE, "cert.pem").
-define(KEY_FILE, "key.pem").
-define(KEY_BITS, 2048).
-define(CERT_DAYS, 3650).  % 10 years

%%-------------------------------------------------------------------
%% API Functions
%%-------------------------------------------------------------------

%% @doc Initialize the pperl directory structure.
-spec init() -> ok | {error, term()}.
init() ->
    Dirs = [
        base_dir(),
        identity_dir(),
        trusted_dir()
    ],
    lists:foreach(fun(Dir) ->
        case filelib:ensure_dir(filename:join(Dir, "dummy")) of
            ok -> ok;
            {error, Reason} -> throw({error, {mkdir, Dir, Reason}})
        end
    end, Dirs),
    ok.

%% @doc Generate a new identity with default name.
-spec generate_identity() -> {ok, Fingerprint :: binary()} | {error, term()}.
generate_identity() ->
    generate_identity(default_common_name()).

%% @doc Generate a new identity with given common name.
-spec generate_identity(CommonName :: string()) -> {ok, Fingerprint :: binary()} | {error, term()}.
generate_identity(CommonName) ->
    init(),
    CertFile = cert_file(),
    KeyFile = key_file(),
    case has_identity() of
        true ->
            {error, identity_exists};
        false ->
            generate_self_signed(CommonName, CertFile, KeyFile)
    end.

%% @doc Check if we have an identity.
-spec has_identity() -> boolean().
has_identity() ->
    filelib:is_regular(cert_file()) andalso
    filelib:is_regular(key_file()).

%% @doc Get our identity (cert and key paths).
-spec get_identity() -> {ok, #{cert => string(), key => string()}} | {error, no_identity}.
get_identity() ->
    case has_identity() of
        true ->
            {ok, #{cert => cert_file(), key => key_file()}};
        false ->
            {error, no_identity}
    end.

%% @doc Get the fingerprint of our certificate.
-spec get_fingerprint() -> {ok, binary()} | {error, term()}.
get_fingerprint() ->
    case has_identity() of
        true ->
            cert_fingerprint(cert_file());
        false ->
            {error, no_identity}
    end.

%% @doc Import a peer's certificate.
-spec import_peer(Name :: string(), CertPath :: string()) -> ok | {error, term()}.
import_peer(Name, CertPath) ->
    import_peer(Name, CertPath, undefined).

%% @doc Import a peer's certificate with optional connection info.
%% ConnStr format: "MODE:IP:PORT" where MODE is L|P|S
-spec import_peer(Name :: string(), CertPath :: string(), ConnStr :: string() | undefined) ->
    ok | {error, term()}.
import_peer(Name, CertPath, ConnStr) ->
    init(),
    case filelib:is_regular(CertPath) of
        true ->
            DestPath = peer_cert_file(Name),
            case file:copy(CertPath, DestPath) of
                {ok, _} ->
                    case ConnStr of
                        undefined -> ok;
                        _ -> set_peer_address(Name, ConnStr)
                    end;
                {error, Reason} -> {error, {copy_failed, Reason}}
            end;
        false ->
            {error, {not_found, CertPath}}
    end.

%% @doc Remove a trusted peer.
-spec remove_peer(Name :: string()) -> ok | {error, term()}.
remove_peer(Name) ->
    CertPath = peer_cert_file(Name),
    ConfPath = peer_conf_file(Name),
    case filelib:is_regular(CertPath) of
        true ->
            file:delete(ConfPath),  %% ignore error if no conf
            file:delete(CertPath);
        false ->
            {error, {not_found, Name}}
    end.

%% @doc List all trusted peers.
-spec list_peers() -> [string()].
list_peers() ->
    case file:list_dir(trusted_dir()) of
        {ok, Files} ->
            [filename:basename(F, ".pem") || F <- Files,
             filename:extension(F) == ".pem"];
        {error, _} ->
            []
    end.

%% @doc Get the certificate path for a peer.
-spec get_peer_cert(Name :: string()) -> {ok, string()} | {error, not_found}.
get_peer_cert(Name) ->
    Path = peer_cert_file(Name),
    case filelib:is_regular(Path) of
        true -> {ok, Path};
        false -> {error, not_found}
    end.

%% @doc Get the fingerprint of a peer's certificate.
-spec get_peer_fingerprint(Name :: string()) -> {ok, binary()} | {error, term()}.
get_peer_fingerprint(Name) ->
    case get_peer_cert(Name) of
        {ok, Path} -> cert_fingerprint(Path);
        Error -> Error
    end.

%% @doc Set connection address for a peer.
%% ConnStr format: "MODE:IP:PORT" where MODE is L (local), P (public), or S (stun)
-spec set_peer_address(Name :: string(), ConnStr :: string()) -> ok | {error, term()}.
set_peer_address(Name, ConnStr) ->
    case get_peer_cert(Name) of
        {ok, _} ->
            case parse_conn_str(ConnStr) of
                {ok, AddrInfo} ->
                    ConfPath = peer_conf_file(Name),
                    Content = io_lib:format("~p.~n", [AddrInfo]),
                    file:write_file(ConfPath, Content);
                {error, _} = Err ->
                    Err
            end;
        {error, _} ->
            {error, {peer_not_found, Name}}
    end.

%% @doc Get connection address for a peer.
-spec get_peer_address(Name :: string()) -> {ok, map()} | {error, term()}.
get_peer_address(Name) ->
    ConfPath = peer_conf_file(Name),
    case file:consult(ConfPath) of
        {ok, [AddrInfo]} -> {ok, AddrInfo};
        {error, enoent} -> {error, not_set};
        {error, Reason} -> {error, Reason}
    end.

%% @doc Get full peer info (cert, fingerprint, address).
-spec get_peer_info(Name :: string()) -> {ok, map()} | {error, term()}.
get_peer_info(Name) ->
    case get_peer_cert(Name) of
        {ok, CertPath} ->
            {ok, FP} = cert_fingerprint(CertPath),
            Address = case get_peer_address(Name) of
                {ok, Addr} -> Addr;
                {error, not_set} -> undefined
            end,
            {ok, #{name => Name, cert => CertPath, fingerprint => FP, address => Address}};
        {error, _} = Err ->
            Err
    end.

%% @doc Get SSL options for DTLS server.
-spec ssl_options() -> [ssl:tls_option()].
ssl_options() ->
    ssl_options(server).

%% @doc Get SSL options for DTLS client or server.
-spec ssl_options(client | server) -> [ssl:tls_option()].
ssl_options(Role) ->
    ssl_options(Role, true).

%% @doc Get SSL options with optional verification.
-spec ssl_options(client | server, Verify :: boolean()) -> [ssl:tls_option()].
ssl_options(Role, Verify) ->
    case get_identity() of
        {ok, #{cert := CertFile, key := KeyFile}} ->
            BaseOpts = [
                {protocol, dtls},
                {certfile, CertFile},
                {keyfile, KeyFile}
            ],
            VerifyOpts = case Verify of
                true ->
                    CaCerts = load_trusted_certs(),
                    [
                        {verify, verify_peer},
                        {cacerts, CaCerts},
                        {verify_fun, verify_peer_fun()}
                    ];
                false ->
                    [{verify, verify_none}]
            end,
            RoleOpts = case {Role, Verify} of
                {server, true} -> [{fail_if_no_peer_cert, true}];
                _ -> []
            end,
            RoleOpts ++ VerifyOpts ++ BaseOpts;
        {error, no_identity} ->
            error(no_identity)
    end.

%% @doc Returns a verify function that checks against trusted peers.
-spec verify_peer_fun() -> {fun(), term()}.
verify_peer_fun() ->
    TrustedFingerprints = load_trusted_fingerprints(),
    {fun verify_peer_cert/3, TrustedFingerprints}.

%%-------------------------------------------------------------------
%% Internal Functions
%%-------------------------------------------------------------------

base_dir() ->
    filename:join(os:getenv("HOME"), ?PPERL_DIR).

identity_dir() ->
    filename:join(base_dir(), ?IDENTITY_DIR).

trusted_dir() ->
    filename:join(base_dir(), ?TRUSTED_DIR).

cert_file() ->
    filename:join(identity_dir(), ?CERT_FILE).

key_file() ->
    filename:join(identity_dir(), ?KEY_FILE).

peer_cert_file(Name) ->
    filename:join(trusted_dir(), Name ++ ".pem").

peer_conf_file(Name) ->
    filename:join(trusted_dir(), Name ++ ".conf").

default_common_name() ->
    {ok, Hostname} = inet:gethostname(),
    "pperl@" ++ Hostname.

%% Generate a self-signed certificate using openssl
generate_self_signed(CommonName, CertFile, KeyFile) ->
    %% Use openssl to generate key and self-signed cert
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:~b -keyout ~s -out ~s "
        "-days ~b -nodes -subj '/CN=~s' 2>/dev/null",
        [?KEY_BITS, KeyFile, CertFile, ?CERT_DAYS, CommonName]
    ),
    case os:cmd(lists:flatten(Cmd)) of
        "" ->
            %% Set restrictive permissions on key
            os:cmd("chmod 600 " ++ KeyFile),
            cert_fingerprint(CertFile);
        Error ->
            {error, {openssl_failed, Error}}
    end.

%% Calculate SHA256 fingerprint of a certificate
cert_fingerprint(CertFile) ->
    case file:read_file(CertFile) of
        {ok, PemBin} ->
            [{'Certificate', DerCert, _}] = public_key:pem_decode(PemBin),
            Hash = crypto:hash(sha256, DerCert),
            {ok, format_fingerprint(Hash)};
        {error, Reason} ->
            {error, {read_cert, Reason}}
    end.

%% Format fingerprint as colon-separated hex string
format_fingerprint(Hash) ->
    Hex = binary:encode_hex(Hash),
    format_fingerprint_hex(Hex, []).

format_fingerprint_hex(<<A, B>>, Acc) ->
    iolist_to_binary(lists:reverse([<<A, B>> | Acc]));
format_fingerprint_hex(<<A, B, Rest/binary>>, Acc) ->
    format_fingerprint_hex(Rest, [<<":">>, <<A, B>> | Acc]).

%% Load all trusted peer fingerprints
load_trusted_fingerprints() ->
    Peers = list_peers(),
    lists:foldl(fun(Name, Acc) ->
        case get_peer_fingerprint(Name) of
            {ok, FP} -> [{Name, FP} | Acc];
            _ -> Acc
        end
    end, [], Peers).

%% Load all trusted peer certificates as DER for cacerts option
load_trusted_certs() ->
    Peers = list_peers(),
    lists:foldl(fun(Name, Acc) ->
        case get_peer_cert(Name) of
            {ok, Path} ->
                case file:read_file(Path) of
                    {ok, PemBin} ->
                        [{'Certificate', DerCert, _}] = public_key:pem_decode(PemBin),
                        [DerCert | Acc];
                    _ -> Acc
                end;
            _ -> Acc
        end
    end, [], Peers).

%% SSL verify callback - check if peer cert is in trusted list
%% For self-signed certs, we accept them if fingerprint matches trusted list
verify_peer_cert(Cert, {bad_cert, selfsigned_peer}, TrustedFingerprints) ->
    %% Self-signed cert - check if it's in our trusted list
    check_fingerprint(Cert, TrustedFingerprints);
verify_peer_cert(_Cert, {bad_cert, _} = Reason, _UserState) ->
    {fail, Reason};
verify_peer_cert(_Cert, {extension, _}, UserState) ->
    {unknown, UserState};
verify_peer_cert(Cert, valid, UserState) ->
    verify_peer_cert(Cert, valid_peer, UserState);
verify_peer_cert(Cert, valid_peer, TrustedFingerprints) ->
    check_fingerprint(Cert, TrustedFingerprints).

check_fingerprint(Cert, TrustedFingerprints) ->
    %% Cert is an OTP certificate record, encode to DER for fingerprint
    DerCert = public_key:pkix_encode('OTPCertificate', Cert, otp),
    Hash = crypto:hash(sha256, DerCert),
    PeerFP = format_fingerprint(Hash),
    %% Check if this fingerprint is trusted
    case lists:keyfind(PeerFP, 2, TrustedFingerprints) of
        {_Name, PeerFP} ->
            {valid, TrustedFingerprints};
        false ->
            {fail, {untrusted_peer, PeerFP}}
    end.

%% Parse connection string "MODE:IP:PORT" -> #{mode, address, port}
parse_conn_str(ConnStr) ->
    case string:split(ConnStr, ":") of
        [ModeStr, Rest] ->
            case parse_mode(ModeStr) of
                {ok, Mode} ->
                    case parse_ip_port(Rest) of
                        {ok, IP, Port} ->
                            {ok, #{mode => Mode, address => IP, port => Port}};
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, invalid_format}
    end.

parse_mode("L") -> {ok, local};
parse_mode("l") -> {ok, local};
parse_mode("P") -> {ok, public};
parse_mode("p") -> {ok, public};
parse_mode("S") -> {ok, stun};
parse_mode("s") -> {ok, stun};
parse_mode(_) -> {error, invalid_mode}.

parse_ip_port(Str) ->
    %% Handle IPv4 "IP:PORT" or IPv6 "[IP]:PORT"
    case string:split(Str, ":", trailing) of
        [IPStr, PortStr] ->
            try
                Port = list_to_integer(PortStr),
                %% Strip brackets for IPv6
                IP = string:trim(IPStr, both, "[]"),
                {ok, IP, Port}
            catch
                _:_ -> {error, invalid_port}
            end;
        _ ->
            {error, invalid_format}
    end.

%% Format address info back to connection string
format_peer_address(#{mode := Mode, address := IP, port := Port}) ->
    ModeStr = case Mode of
        local -> "L";
        public -> "P";
        stun -> "S"
    end,
    io_lib:format("~s:~s:~p", [ModeStr, IP, Port]).
