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

    %% Direct mode (local/public)
    send_direct/3,     %% Send file directly to IP:Port
    recv_direct/2,     %% Receive file on port

    %% Interactive helpers
    init_send/0,       %% Sender: get connection string to share
    init_receive/0,    %% Receiver: get connection string to share
    do_send/2,         %% Sender: send file using peer's connection string
    do_send/3,
    do_receive/2,      %% Receiver: receive file using peer's connection string
    do_receive/3,
    stop_keepalive/1,  %% Stop NAT keepalive (called automatically by do_*)

    %% Testing
    test_local/0
]).

-define(STUN_SERVERS, [
    {"stun.l.google.com", 19302},
    {"stun1.l.google.com", 19302}
]).
-define(HOLE_PUNCH_INTERVAL, 500).   %% 500ms between punches
-define(HOLE_PUNCH_DURATION, 30000). %% Punch for 30 seconds total
-define(CONNECT_TIMEOUT, 30000).     %% 30 second connection timeout

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
    io:format("~n=== CONNECT to ~s:~p ===~n", [inet:ntoa(PeerIP), PeerPort]),

    %% Open our UDP socket on a random port
    case gen_udp:open(0, [binary, {active, false}, {reuseaddr, true}]) of
        {ok, UdpSocket} ->
            {ok, LocalPort} = inet:port(UdpSocket),
            io:format("[connect] Local UDP port: ~p~n", [LocalPort]),

            %% Do STUN to establish our NAT mapping
            io:format("[connect] Doing STUN...~n"),
            case stun_with_socket(UdpSocket) of
                {ok, OurPublic} ->
                    io:format("[connect] Our public address: ~p~n", [OurPublic]),

                    %% Open a second socket for continuous punching during DTLS
                    {ok, PunchSocket} = gen_udp:open(LocalPort,
                        [binary, {active, false}, {reuseaddr, true}]),

                    %% Start continuous puncher (runs during DTLS handshake)
                    io:format("[connect] Starting continuous hole punching...~n"),
                    Puncher = start_puncher(PunchSocket, PeerIP, PeerPort),

                    %% Prepare the main socket for DTLS
                    pperl_udp_transport:prepare(UdpSocket, LocalPort),

                    %% Connect via DTLS (puncher keeps running)
                    io:format("[connect] Attempting DTLS connect...~n"),
                    Result = dtls_connect_punched(PeerIP, PeerPort, LocalPort, Timeout),

                    %% Stop puncher
                    stop_puncher(Puncher),
                    gen_udp:close(PunchSocket),

                    case Result of
                        {ok, _} -> io:format("[connect] SUCCESS!~n");
                        {error, E} -> io:format("[connect] FAILED: ~p~n", [E])
                    end,
                    Result;
                {error, _} = Err ->
                    io:format("[connect] STUN failed: ~p~n", [Err]),
                    gen_udp:close(UdpSocket),
                    Err
            end;
        {error, _} = Err ->
            io:format("[connect] Failed to open socket: ~p~n", [Err]),
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

%% @doc Accept using a pre-punched socket via custom transport.
-spec accept_punched(inet:port_number(), string()) -> {ok, string()} | {error, term()}.
accept_punched(LocalPort, DestDir) ->
    accept_punched(LocalPort, DestDir, ?CONNECT_TIMEOUT).

-spec accept_punched(inet:port_number(), string(), timeout()) -> {ok, string()} | {error, term()}.
accept_punched(LocalPort, DestDir, Timeout) ->
    application:ensure_all_started(ssl),
    SslOpts = pperl_identity:ssl_options(server) ++ [
        {reuseaddr, true},
        {active, false},
        {mode, binary},
        %% Use custom transport to reuse punched socket
        {cb_info, {pperl_udp_transport, udp, udp_closed, udp_error, udp_passive}}
    ],
    case ssl:listen(LocalPort, SslOpts) of
        {ok, ListenSocket} ->
            io:format("Listening on port ~p (punched socket)~n", [LocalPort]),
            Result = case ssl:transport_accept(ListenSocket, Timeout) of
                {ok, Socket} ->
                    case ssl:handshake(Socket, Timeout) of
                        {ok, SslSocket} ->
                            %% Receive the file
                            FileResult = pperl_transfer:recv_file(SslSocket, DestDir),
                            ssl:close(SslSocket),
                            FileResult;
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end,
            ssl:close(ListenSocket),
            Result;
        {error, _} = Err ->
            pperl_udp_transport:unprepare(LocalPort),
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
%% Direct Mode (local/public networks)
%%===================================================================

%% @doc Send a file directly to a peer (no STUN/hole punching).
%% Use for local network or public IP peers.
-spec send_direct(string(), string(), inet:port_number()) ->
    ok | {error, term()}.
send_direct(FilePath, Host, Port) ->
    io:format("Connecting to ~s:~p...~n", [Host, Port]),
    case pperl_dtls:connect(Host, Port) of
        {ok, Socket} ->
            io:format("Connected, sending file...~n"),
            Result = pperl_transfer:send_file(Socket, FilePath,
                                               filename:basename(FilePath)),
            pperl_dtls:close(Socket),
            Result;
        {error, _} = Err ->
            Err
    end.

%% @doc Receive a file directly (listen on port).
%% Use for local network or public IP peers.
-spec recv_direct(string(), inet:port_number()) ->
    {ok, string()} | {error, term()}.
recv_direct(DestDir, Port) ->
    io:format("Listening on port ~p...~n", [Port]),
    case pperl_dtls:listen(Port) of
        {ok, ListenSocket} ->
            io:format("Waiting for connection...~n"),
            case pperl_dtls:accept(ListenSocket) of
                {ok, Socket} ->
                    io:format("Connected, receiving file...~n"),
                    Result = pperl_transfer:recv_file(Socket, DestDir),
                    pperl_dtls:close(Socket),
                    pperl_dtls:close(ListenSocket),
                    Result;
                {error, _} = Err ->
                    pperl_dtls:close(ListenSocket),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%%===================================================================
%% Interactive Workflow
%%===================================================================
%%
%% These functions help with the manual P2P connection workflow.
%% IMPORTANT: The socket must stay open between init and do phases!
%%
%% SENDER:                                    RECEIVER:
%% 1. {ok, Ctx} = init_send()                 1. {ok, Ctx} = init_receive()
%% 2. Share Ctx.conn_str with receiver        2. Share Ctx.conn_str with sender
%% 3. do_send(Ctx, File, RecvConnStr)         3. do_receive(Ctx, Dir, SendConnStr)
%%
%% The Ctx (context) keeps the socket alive so the NAT mapping is preserved.
%%

-record(p2p_ctx, {
    socket :: gen_udp:socket(),
    local_port :: inet:port_number(),
    public_addr :: {inet:ip_address(), inet:port_number()},
    conn_str :: string(),
    keepalive :: pid() | undefined  %% Background process keeping NAT mapping alive
}).

%% @doc Initialize as sender - returns context with socket kept open.
-spec init_send() -> {ok, #p2p_ctx{}} | {error, term()}.
init_send() ->
    io:format("~n=== INIT SENDER ===~n"),

    %% Open UDP socket
    case gen_udp:open(0, [binary, {active, false}, {reuseaddr, true}]) of
        {ok, Socket} ->
            {ok, LocalPort} = inet:port(Socket),
            io:format("[init_send] Local port: ~p~n", [LocalPort]),

            %% Do STUN to get our public address
            io:format("[init_send] Doing STUN...~n"),
            case stun_with_socket(Socket) of
                {ok, {PubIP, PubPort} = PubAddr} ->
                    io:format("[init_send] Public address: ~s:~p~n",
                              [inet:ntoa(PubIP), PubPort]),

                    %% Build connection string
                    {ok, FP} = pperl_identity:get_fingerprint(),
                    ShortFP = binary:part(FP, 0, 16),
                    ConnStr = lists:flatten(
                        io_lib:format("~s:~p:~s", [inet:ntoa(PubIP), PubPort, ShortFP])),

                    io:format("~n>>> Your connection string: ~s~n", [ConnStr]),
                    io:format("~nShare this with receiver, get their string, then run:~n"),
                    io:format("  pperl_p2p:do_send(Ctx, \"file.txt\", \"<receiver_conn_str>\").~n~n"),

                    %% Start keepalive to maintain NAT mapping while user exchanges strings
                    Keepalive = start_keepalive(Socket, LocalPort),
                    io:format("[init_send] NAT keepalive started (refreshes every 10s)~n"),

                    Ctx = #p2p_ctx{
                        socket = Socket,
                        local_port = LocalPort,
                        public_addr = PubAddr,
                        conn_str = ConnStr,
                        keepalive = Keepalive
                    },
                    {ok, Ctx};
                {error, _} = Err ->
                    gen_udp:close(Socket),
                    io:format("[init_send] STUN failed: ~p~n", [Err]),
                    Err
            end;
        {error, _} = Err ->
            io:format("[init_send] Failed to open socket: ~p~n", [Err]),
            Err
    end.

%% @doc Initialize as receiver - returns context with socket kept open.
-spec init_receive() -> {ok, #p2p_ctx{}} | {error, term()}.
init_receive() ->
    io:format("~n=== INIT RECEIVER ===~n"),

    %% Open UDP socket
    case gen_udp:open(0, [binary, {active, false}, {reuseaddr, true}]) of
        {ok, Socket} ->
            {ok, LocalPort} = inet:port(Socket),
            io:format("[init_receive] Local port: ~p~n", [LocalPort]),

            %% Do STUN to get our public address
            io:format("[init_receive] Doing STUN...~n"),
            case stun_with_socket(Socket) of
                {ok, {PubIP, PubPort} = PubAddr} ->
                    io:format("[init_receive] Public address: ~s:~p~n",
                              [inet:ntoa(PubIP), PubPort]),

                    %% Build connection string
                    {ok, FP} = pperl_identity:get_fingerprint(),
                    ShortFP = binary:part(FP, 0, 16),
                    ConnStr = lists:flatten(
                        io_lib:format("~s:~p:~s", [inet:ntoa(PubIP), PubPort, ShortFP])),

                    io:format("~n>>> Your connection string: ~s~n", [ConnStr]),
                    io:format("~nShare this with sender, get their string, then run:~n"),
                    io:format("  pperl_p2p:do_receive(Ctx, \"/dest/dir\", \"<sender_conn_str>\").~n~n"),

                    %% Start keepalive to maintain NAT mapping while user exchanges strings
                    Keepalive = start_keepalive(Socket, LocalPort),
                    io:format("[init_receive] NAT keepalive started (refreshes every 10s)~n"),

                    Ctx = #p2p_ctx{
                        socket = Socket,
                        local_port = LocalPort,
                        public_addr = PubAddr,
                        conn_str = ConnStr,
                        keepalive = Keepalive
                    },
                    {ok, Ctx};
                {error, _} = Err ->
                    gen_udp:close(Socket),
                    io:format("[init_receive] STUN failed: ~p~n", [Err]),
                    Err
            end;
        {error, _} = Err ->
            io:format("[init_receive] Failed to open socket: ~p~n", [Err]),
            Err
    end.

%% @doc Send a file using the context from init_send().
-spec do_send(#p2p_ctx{}, string(), string()) -> ok | {error, term()}.
do_send(#p2p_ctx{socket = UdpSocket, local_port = LocalPort, keepalive = Keepalive}, FilePath, PeerConnStr) ->
    %% Stop keepalive - we're now actively connecting
    stop_keepalive(Keepalive),

    case parse_conn_str(PeerConnStr) of
        {ok, PeerIP, PeerPort, _PeerFP} ->
            io:format("~n=== SEND to ~s:~p ===~n", [inet:ntoa(PeerIP), PeerPort]),

            %% Open a second socket for continuous punching during DTLS
            {ok, PunchSocket} = gen_udp:open(LocalPort,
                [binary, {active, false}, {reuseaddr, true}]),

            %% Start continuous puncher
            io:format("[send] Starting continuous hole punching...~n"),
            Puncher = start_puncher(PunchSocket, PeerIP, PeerPort),

            %% Prepare the main socket for DTLS
            pperl_udp_transport:prepare(UdpSocket, LocalPort),

            %% Connect via DTLS
            io:format("[send] Attempting DTLS connect...~n"),
            Result = case dtls_connect_punched(PeerIP, PeerPort, LocalPort, ?CONNECT_TIMEOUT) of
                {ok, DtlsSocket} ->
                    io:format("[send] Connected! Sending file...~n"),
                    SendResult = pperl_transfer:send_file(DtlsSocket, FilePath,
                                                          filename:basename(FilePath)),
                    ssl:close(DtlsSocket),
                    SendResult;
                {error, _} = Err ->
                    Err
            end,

            %% Stop puncher
            stop_puncher(Puncher),
            gen_udp:close(PunchSocket),

            case Result of
                ok -> io:format("[send] SUCCESS!~n");
                {error, E} -> io:format("[send] FAILED: ~p~n", [E])
            end,
            Result;
        {error, _} = Err ->
            io:format("[send] Invalid connection string: ~p~n", [Err]),
            Err
    end.

%% @doc Receive a file using the context from init_receive().
-spec do_receive(#p2p_ctx{}, string(), string()) -> {ok, string()} | {error, term()}.
do_receive(#p2p_ctx{socket = UdpSocket, local_port = LocalPort, keepalive = Keepalive}, DestDir, PeerConnStr) ->
    %% Stop keepalive - we're now actively connecting
    stop_keepalive(Keepalive),

    case parse_conn_str(PeerConnStr) of
        {ok, PeerIP, PeerPort, _PeerFP} ->
            io:format("~n=== RECEIVE from ~s:~p ===~n", [inet:ntoa(PeerIP), PeerPort]),

            %% Open a second socket for continuous punching during DTLS
            {ok, PunchSocket} = gen_udp:open(LocalPort,
                [binary, {active, false}, {reuseaddr, true}]),

            %% Start continuous puncher
            io:format("[receive] Starting continuous hole punching...~n"),
            Puncher = start_puncher(PunchSocket, PeerIP, PeerPort),

            %% Prepare the main socket for DTLS
            pperl_udp_transport:prepare(UdpSocket, LocalPort),

            %% Accept connection
            io:format("[receive] Waiting for DTLS connection...~n"),
            Result = accept_punched(LocalPort, DestDir),

            %% Stop puncher
            stop_puncher(Puncher),
            gen_udp:close(PunchSocket),

            case Result of
                {ok, _} -> io:format("[receive] SUCCESS!~n");
                {error, E} -> io:format("[receive] FAILED: ~p~n", [E])
            end,
            Result;
        {error, _} = Err ->
            io:format("[receive] Invalid connection string: ~p~n", [Err]),
            Err
    end.

%% Legacy wrappers for backwards compatibility (create new socket each time - not recommended)
%% @doc Legacy: Send without pre-initialized context (creates new socket).
-spec do_send(string(), string()) -> ok | {error, term()}.
do_send(FilePath, PeerConnStr) ->
    io:format("WARNING: Using legacy do_send/2 - creating new socket~n"),
    io:format("         Recommended: use init_send() then do_send/3~n~n"),
    case init_send() of
        {ok, Ctx} -> do_send(Ctx, FilePath, PeerConnStr);
        {error, _} = Err -> Err
    end.

%% @doc Legacy: Receive without pre-initialized context (creates new socket).
-spec do_receive(string(), string()) -> {ok, string()} | {error, term()}.
do_receive(DestDir, PeerConnStr) ->
    io:format("WARNING: Using legacy do_receive/2 - creating new socket~n"),
    io:format("         Recommended: use init_receive() then do_receive/3~n~n"),
    case init_receive() of
        {ok, Ctx} -> do_receive(Ctx, DestDir, PeerConnStr);
        {error, _} = Err -> Err
    end.

%% Parse connection string "IP:Port:Fingerprint"
parse_conn_str(ConnStr) ->
    case string:split(ConnStr, ":") of
        [IPStr, ConnStr1] ->
	    case string:split(ConnStr1, ":") of
		[PortStr, FPStr] ->
		    case inet:parse_address(IPStr) of
			{ok, IP} ->
			    Port = list_to_integer(PortStr),
			    {ok, IP, Port, FPStr};
			{error, _} ->
			    {error, invalid_ip}
		    end;
		_ ->
		    {error, invalid_format}
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

%% Send hole-punching packets (blocking, limited duration)
hole_punch(UdpSocket, PeerIP, PeerPort) ->
    hole_punch(UdpSocket, PeerIP, PeerPort, ?HOLE_PUNCH_DURATION).

hole_punch(UdpSocket, PeerIP, PeerPort, Duration) ->
    EndTime = erlang:monotonic_time(millisecond) + Duration,
    hole_punch_loop(UdpSocket, PeerIP, PeerPort, EndTime, 0).

hole_punch_loop(UdpSocket, PeerIP, PeerPort, EndTime, Count) ->
    Now = erlang:monotonic_time(millisecond),
    case Now < EndTime of
        true ->
            Punch = <<"pperl-punch:", (integer_to_binary(Count))/binary>>,
            case gen_udp:send(UdpSocket, PeerIP, PeerPort, Punch) of
                ok ->
                    case Count rem 10 of
                        0 -> io:format("  [punch] #~p to ~s:~p~n",
                                       [Count, inet:ntoa(PeerIP), PeerPort]);
                        _ -> ok
                    end;
                {error, E} ->
                    io:format("  [punch] ERROR: ~p~n", [E])
            end,
            timer:sleep(?HOLE_PUNCH_INTERVAL),
            hole_punch_loop(UdpSocket, PeerIP, PeerPort, EndTime, Count + 1);
        false ->
            io:format("  [punch] Done after ~p packets~n", [Count]),
            ok
    end.

%% Start continuous hole punching in background (returns pid to stop it)
start_puncher(UdpSocket, PeerIP, PeerPort) ->
    spawn_link(fun() ->
        io:format("  [puncher] Starting continuous punch to ~s:~p~n",
                  [inet:ntoa(PeerIP), PeerPort]),
        puncher_loop(UdpSocket, PeerIP, PeerPort, 0)
    end).

puncher_loop(UdpSocket, PeerIP, PeerPort, Count) ->
    receive
        stop ->
            io:format("  [puncher] Stopped after ~p packets~n", [Count]),
            ok
    after 0 ->
        Punch = <<"pperl-punch:", (integer_to_binary(Count))/binary>>,
        gen_udp:send(UdpSocket, PeerIP, PeerPort, Punch),
        case Count rem 20 of
            0 -> io:format("  [puncher] #~p~n", [Count]);
            _ -> ok
        end,
        timer:sleep(?HOLE_PUNCH_INTERVAL),
        puncher_loop(UdpSocket, PeerIP, PeerPort, Count + 1)
    end.

stop_puncher(Pid) ->
    Pid ! stop.

%% NAT keepalive - periodically sends STUN binding request to keep NAT mapping alive
%% This runs in the background while user is exchanging connection strings
-define(KEEPALIVE_INTERVAL, 10000).  %% 10 seconds

start_keepalive(Socket, LocalPort) ->
    %% Open a second socket on same port for keepalive
    case gen_udp:open(LocalPort, [binary, {active, false}, {reuseaddr, true}]) of
        {ok, KeepaliveSocket} ->
            spawn_link(fun() -> keepalive_loop(KeepaliveSocket, 0) end);
        {error, _} ->
            %% Fallback: use main socket (less ideal but works)
            spawn_link(fun() -> keepalive_loop(Socket, 0) end)
    end.

keepalive_loop(Socket, Count) ->
    receive
        stop ->
            io:format("  [keepalive] Stopped after ~p refreshes~n", [Count]),
            %% Don't close the socket - it might be the main one
            ok
    after ?KEEPALIVE_INTERVAL ->
        %% Send STUN binding request to refresh NAT mapping
        case send_stun_keepalive(Socket) of
            ok ->
                case Count rem 6 of  %% Log every minute
                    0 -> io:format("  [keepalive] NAT refresh #~p~n", [Count]);
                    _ -> ok
                end;
            {error, E} ->
                io:format("  [keepalive] ERROR: ~p~n", [E])
        end,
        keepalive_loop(Socket, Count + 1)
    end.

send_stun_keepalive(Socket) ->
    %% Send to Google STUN server to refresh NAT mapping
    {Request, _TxnId} = stun_codec:binding_request(),
    case inet:getaddr("stun.l.google.com", inet) of
        {ok, IP} ->
            gen_udp:send(Socket, IP, 19302, Request);
        {error, _} = Err ->
            Err
    end.

stop_keepalive(undefined) ->
    ok;
stop_keepalive(Pid) when is_pid(Pid) ->
    Pid ! stop.

%% DTLS connect reusing a pre-punched socket via custom transport
dtls_connect_punched(PeerIP, PeerPort, LocalPort, Timeout) ->
    application:ensure_all_started(ssl),
    SslOpts = pperl_identity:ssl_options(client) ++ [
        {active, false},
        {mode, binary},
        {port, LocalPort},
        {reuseaddr, true},
        %% Use custom transport to reuse the punched socket
        {cb_info, {pperl_udp_transport, udp, udp_closed, udp_error, udp_passive}}
    ],
    Host = case PeerIP of
        {A,B,C,D} -> inet:ntoa({A,B,C,D});
        _ -> PeerIP
    end,
    case ssl:connect(Host, PeerPort, SslOpts, Timeout) of
        {ok, _} = Ok ->
            Ok;
        {error, _} = Err ->
            %% Clean up prepared socket on failure
            pperl_udp_transport:unprepare(LocalPort),
            Err
    end.

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
