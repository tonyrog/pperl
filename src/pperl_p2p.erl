%%%-------------------------------------------------------------------
%%% @doc P2P connection establishment with NAT traversal.
%%%
%%% Flow:
%%%   1. discover()     - Get our public IP:port via STUN
%%%   2. Exchange addresses out-of-band (copy/paste, QR code, etc)
%%%   3. connect()      - Hole punch and establish DTLS
%%%
%%% The tricky part: we need to use the SAME UDP socket for STUN,
%%% hole punching, and DTLS to maintain NAT mappings.
%%%-------------------------------------------------------------------
-module(pperl_p2p).

-export([
    %% Discovery
    discover/0,
    discover/1,

    %% Connection (after address exchange)
    connect/2,
    connect/3,
    accept/1,
    accept/2,

    %% High-level workflow
    send_file_to/3,
    receive_file_from/2,

    %% Interactive helpers
    init_send/0,       %% Sender: get connection string to share
    init_receive/0,    %% Receiver: get connection string to share
    do_send/2,         %% Sender: send file using peer's connection string
    do_receive/2,      %% Receiver: receive file using peer's connection string

    %% Testing
    test_local/0
]).

-define(STUN_SERVERS, [
    {"stun.l.google.com", 19302},
    {"stun1.l.google.com", 19302}
]).
-define(HOLE_PUNCH_ATTEMPTS, 10).
-define(HOLE_PUNCH_INTERVAL, 100).
-define(CONNECT_TIMEOUT, 10000).

%%===================================================================
%% Discovery
%%===================================================================

%% @doc Discover our public address using STUN.
%% Returns the address to share with the peer.
-spec discover() -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
discover() ->
    discover(?STUN_SERVERS).

-spec discover([{string(), inet:port_number()}]) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
discover(StunServers) ->
    stun_client:get_mapped_address(StunServers).

%%===================================================================
%% Connection
%%===================================================================

%% @doc Connect to a peer after exchanging addresses.
%% PeerAddr is the peer's public address from their discover().
-spec connect(inet:ip_address(), inet:port_number()) ->
    {ok, ssl:sslsocket()} | {error, term()}.
connect(PeerIP, PeerPort) ->
    connect(PeerIP, PeerPort, ?CONNECT_TIMEOUT).

-spec connect(inet:ip_address(), inet:port_number(), timeout()) ->
    {ok, ssl:sslsocket()} | {error, term()}.
connect(PeerIP, PeerPort, Timeout) ->
    %% Open our UDP socket on a random port
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, UdpSocket} ->
            {ok, LocalPort} = inet:port(UdpSocket),
            io:format("Local UDP port: ~p~n", [LocalPort]),

            %% Do STUN to establish our NAT mapping
            case stun_with_socket(UdpSocket) of
                {ok, OurPublic} ->
                    io:format("Our public address: ~p~n", [OurPublic]),

                    %% Hole punch - send packets to peer
                    io:format("Hole punching to ~p:~p~n", [PeerIP, PeerPort]),
                    hole_punch(UdpSocket, PeerIP, PeerPort),

                    %% Now try DTLS connection
                    %% Close UDP socket first - DTLS will open its own
                    gen_udp:close(UdpSocket),

                    %% Connect via DTLS using the same local port
                    dtls_connect(PeerIP, PeerPort, LocalPort, Timeout);
                {error, _} = Err ->
                    gen_udp:close(UdpSocket),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Accept a connection from a peer.
%% LocalPort should be the port we advertised via discover().
-spec accept(inet:port_number()) -> {ok, ssl:sslsocket()} | {error, term()}.
accept(LocalPort) ->
    accept(LocalPort, ?CONNECT_TIMEOUT).

-spec accept(inet:port_number(), timeout()) -> {ok, ssl:sslsocket()} | {error, term()}.
accept(LocalPort, Timeout) ->
    %% Listen on the specific port we advertised
    SslOpts = pperl_identity:ssl_options(server) ++ [
        {reuseaddr, true},
        {active, false},
        {mode, binary}
    ],
    case ssl:listen(LocalPort, SslOpts) of
        {ok, ListenSocket} ->
            io:format("Listening on port ~p~n", [LocalPort]),
            Result = case ssl:transport_accept(ListenSocket, Timeout) of
                {ok, Socket} ->
                    case ssl:handshake(Socket, Timeout) of
                        {ok, SslSocket} -> {ok, SslSocket};
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end,
            ssl:close(ListenSocket),
            Result;
        {error, _} = Err ->
            Err
    end.

%%===================================================================
%% High-level API
%%===================================================================

%% @doc Send a file to a peer at given address.
-spec send_file_to(string(), inet:ip_address(), inet:port_number()) ->
    ok | {error, term()}.
send_file_to(FilePath, PeerIP, PeerPort) ->
    case connect(PeerIP, PeerPort) of
        {ok, Socket} ->
            Result = pperl_transfer:send_file(Socket, FilePath,
                                               filename:basename(FilePath)),
            ssl:close(Socket),
            Result;
        {error, _} = Err ->
            Err
    end.

%% @doc Receive a file from a peer.
-spec receive_file_from(inet:port_number(), string()) ->
    {ok, string()} | {error, term()}.
receive_file_from(LocalPort, DestDir) ->
    case accept(LocalPort) of
        {ok, Socket} ->
            Result = pperl_transfer:recv_file(Socket, DestDir),
            ssl:close(Socket),
            Result;
        {error, _} = Err ->
            Err
    end.

%%===================================================================
%% Interactive Workflow
%%===================================================================
%%
%% These functions help with the manual P2P connection workflow:
%%
%% SENDER:                           RECEIVER:
%% 1. init_send() -> ConnStr         1. init_receive() -> ConnStr
%% 2. Share ConnStr with receiver    2. Share ConnStr with sender
%% 3. do_send(File, RecvConnStr)     3. do_receive(Dir, SendConnStr)
%%

%% @doc Initialize as sender - returns connection string to share.
-spec init_send() -> {ok, string()} | {error, term()}.
init_send() ->
    case discover() of
        {ok, {IP, Port}} ->
            %% Get our fingerprint for verification
            {ok, FP} = pperl_identity:get_fingerprint(),
            %% Format: IP:Port:Fingerprint (truncated)
            ShortFP = binary:part(FP, 0, 16),
            ConnStr = io_lib:format("~s:~p:~s", [inet:ntoa(IP), Port, ShortFP]),
            {ok, lists:flatten(ConnStr)};
        {error, _} = Err ->
            Err
    end.

%% @doc Initialize as receiver - returns connection string to share.
-spec init_receive() -> {ok, string(), inet:port_number()} | {error, term()}.
init_receive() ->
    %% Open a listening socket first to get our port
    case gen_udp:open(0, [binary]) of
        {ok, Sock} ->
            {ok, LocalPort} = inet:port(Sock),
            gen_udp:close(Sock),

            %% Now discover our public address using that knowledge
            %% (In practice, the NAT mapping might use a different port)
            case discover() of
                {ok, {IP, _StunPort}} ->
                    {ok, FP} = pperl_identity:get_fingerprint(),
                    ShortFP = binary:part(FP, 0, 16),
                    %% Use local port - hope NAT preserves it (works for many NATs)
                    ConnStr = io_lib:format("~s:~p:~s", [inet:ntoa(IP), LocalPort, ShortFP]),
                    {ok, lists:flatten(ConnStr), LocalPort};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Send a file using peer's connection string.
-spec do_send(string(), string()) -> ok | {error, term()}.
do_send(FilePath, PeerConnStr) ->
    case parse_conn_str(PeerConnStr) of
        {ok, PeerIP, PeerPort, _PeerFP} ->
            io:format("Connecting to ~s:~p~n", [inet:ntoa(PeerIP), PeerPort]),
            case connect(PeerIP, PeerPort) of
                {ok, Socket} ->
                    Result = pperl_transfer:send_file(Socket, FilePath,
                                                       filename:basename(FilePath)),
                    ssl:close(Socket),
                    Result;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Receive a file using sender's connection string for hole punching.
-spec do_receive(string(), string()) -> {ok, string()} | {error, term()}.
do_receive(DestDir, PeerConnStr) ->
    case parse_conn_str(PeerConnStr) of
        {ok, PeerIP, PeerPort, _PeerFP} ->
            %% We need to:
            %% 1. Listen on our port
            %% 2. Hole punch to peer
            %% 3. Accept their connection

            %% First, get our own address
            {ok, _OurConnStr, LocalPort} = init_receive(),

            io:format("Listening on port ~p, hole punching to ~s:~p~n",
                      [LocalPort, inet:ntoa(PeerIP), PeerPort]),

            %% Start hole punching in background
            spawn(fun() ->
                {ok, Sock} = gen_udp:open(LocalPort, [binary, {reuseaddr, true}]),
                hole_punch(Sock, PeerIP, PeerPort),
                gen_udp:close(Sock)
            end),

            %% Accept connection
            timer:sleep(500), %% Let hole punching start
            receive_file_from(LocalPort, DestDir);
        {error, _} = Err ->
            Err
    end.

%% Parse connection string "IP:Port:Fingerprint"
parse_conn_str(ConnStr) ->
    case string:split(ConnStr, ":", all) of
        [IPStr, PortStr, FPStr] ->
            case inet:parse_address(IPStr) of
                {ok, IP} ->
                    Port = list_to_integer(PortStr),
                    {ok, IP, Port, FPStr};
                {error, _} ->
                    {error, invalid_ip}
            end;
        _ ->
            {error, invalid_format}
    end.

%%===================================================================
%% Internal
%%===================================================================

%% Do STUN query using an existing socket
stun_with_socket(UdpSocket) ->
    stun_with_socket(UdpSocket, ?STUN_SERVERS).

stun_with_socket(_UdpSocket, []) ->
    {error, no_stun_response};
stun_with_socket(UdpSocket, [{Host, Port} | Rest]) ->
    {Request, TxnId} = stun_codec:binding_request(),
    case inet:getaddr(Host, inet) of
        {ok, IP} ->
            ok = gen_udp:send(UdpSocket, IP, Port, Request),
            case gen_udp:recv(UdpSocket, 0, 3000) of
                {ok, {_, _, Data}} ->
                    case stun_codec:decode(Data) of
                        {ok, #{class := success_response, txn_id := TxnId, attrs := Attrs}} ->
                            extract_mapped_address(Attrs);
                        _ ->
                            stun_with_socket(UdpSocket, Rest)
                    end;
                {error, timeout} ->
                    stun_with_socket(UdpSocket, Rest);
                {error, _} = Err ->
                    Err
            end;
        {error, _} ->
            stun_with_socket(UdpSocket, Rest)
    end.

extract_mapped_address(Attrs) ->
    case lists:keyfind(xor_mapped_address, 1, Attrs) of
        {xor_mapped_address, Addr} -> {ok, Addr};
        false ->
            case lists:keyfind(mapped_address, 1, Attrs) of
                {mapped_address, Addr} -> {ok, Addr};
                false -> {error, no_mapped_address}
            end
    end.

%% Send hole-punching packets
hole_punch(UdpSocket, PeerIP, PeerPort) ->
    hole_punch(UdpSocket, PeerIP, PeerPort, ?HOLE_PUNCH_ATTEMPTS).

hole_punch(_UdpSocket, _PeerIP, _PeerPort, 0) ->
    ok;
hole_punch(UdpSocket, PeerIP, PeerPort, N) ->
    %% Send a simple punch packet
    Punch = <<"pperl-punch">>,
    gen_udp:send(UdpSocket, PeerIP, PeerPort, Punch),
    timer:sleep(?HOLE_PUNCH_INTERVAL),
    hole_punch(UdpSocket, PeerIP, PeerPort, N - 1).

%% DTLS connect with specific local port
dtls_connect(PeerIP, PeerPort, LocalPort, Timeout) ->
    application:ensure_all_started(ssl),
    SslOpts = pperl_identity:ssl_options(client) ++ [
        {active, false},
        {mode, binary},
        {port, LocalPort},  %% Use same local port for NAT binding
        {reuseaddr, true}
    ],
    %% Convert IP tuple to string if needed
    Host = case PeerIP of
        {A,B,C,D} -> inet:ntoa({A,B,C,D});
        _ -> PeerIP
    end,
    ssl:connect(Host, PeerPort, SslOpts, Timeout).

%%===================================================================
%% Testing
%%===================================================================

%% @doc Test P2P locally (bypasses NAT traversal).
test_local() ->
    Port = 9990,

    %% Ensure we trust ourselves
    case pperl_identity:list_peers() of
        [] ->
            {ok, #{cert := CertPath}} = pperl_identity:get_identity(),
            pperl_identity:import_peer("myself", CertPath);
        _ -> ok
    end,

    Self = self(),

    %% Receiver using pperl_dtls (known to work)
    spawn(fun() ->
        io:format("[Receiver] Starting~n"),
        {ok, ListenSocket} = pperl_dtls:listen(Port),
        case pperl_dtls:accept(ListenSocket) of
            {ok, Socket} ->
                Result = pperl_transfer:recv_file(Socket, "/tmp"),
                io:format("[Receiver] Result: ~p~n", [Result]),
                pperl_dtls:close(Socket),
                Self ! {done, Result};
            {error, Reason} ->
                io:format("[Receiver] Accept error: ~p~n", [Reason]),
                Self ! {done, {error, Reason}}
        end
    end),

    timer:sleep(200),

    %% Sender - connect directly (no hole punching needed locally)
    io:format("[Sender] Connecting~n"),
    case pperl_dtls:connect("localhost", Port) of
        {ok, Socket} ->
            io:format("[Sender] Connected, sending file~n"),
            Result = pperl_transfer:send_file(Socket, "/etc/passwd", "passwd"),
            io:format("[Sender] Result: ~p~n", [Result]),
            pperl_dtls:close(Socket);
        {error, Reason} ->
            io:format("[Sender] Connect error: ~p~n", [Reason])
    end,

    receive
        {done, R} -> R
    after 30000 ->
        {error, timeout}
    end.
