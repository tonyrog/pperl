%%%-------------------------------------------------------------------
%%% @doc Diagnostic tools for debugging P2P NAT traversal.
%%%
%%% Usage:
%%%   1. On both machines, run: pperl_diag:probe()
%%%   2. Exchange the connection strings
%%%   3. On both machines, run: pperl_diag:test_punch(PeerConnStr)
%%%
%%% This will show if packets are getting through in both directions.
%%%-------------------------------------------------------------------
-module(pperl_diag).

-export([
    %% Quick diagnostics
    probe/0,              %% Get our public address and connection string
    test_punch/1,         %% Test hole punching with peer (new socket - quick test)
    test_punch/2,         %% Test hole punching with existing socket (correct way)

    %% Lower level tools
    stun_info/0,          %% Detailed STUN information
    listen_raw/1,         %% Listen for raw UDP packets
    send_raw/3,           %% Send raw UDP packets

    %% NAT type detection
    nat_type/0
]).

-export([parse_addr/1]).

-define(STUN_SERVERS, [
    {"stun.l.google.com", 19302},
    {"stun1.l.google.com", 19302},
    {"stun2.l.google.com", 19302}
]).

%%===================================================================
%% Quick Diagnostics
%%===================================================================

%% @doc Get our public address and generate a connection string.
%% Returns the socket so it can be reused for test_punch.
-spec probe() -> {ok, gen_udp:socket(), string()} | error.
probe() ->
    io:format("~n=== PPERL Network Diagnostic ===~n~n"),

    %% Local info
    {ok, Hostname} = inet:gethostname(),
    {ok, LocalAddrs} = inet:getifaddrs(),
    io:format("Hostname: ~s~n", [Hostname]),
    io:format("Local interfaces:~n"),
    lists:foreach(fun({Name, Props}) ->
        case proplists:get_value(addr, Props) of
            {_,_,_,_} = Addr when element(1, Addr) =/= 127 ->
                io:format("  ~s: ~s~n", [Name, inet:ntoa(Addr)]);
            _ -> ok
        end
    end, LocalAddrs),

    io:format("~n"),

    %% STUN probe
    case stun_probe() of
        {ok, Socket, LocalPort, PublicAddr} ->
            {PubIP, PubPort} = PublicAddr,
            io:format("STUN result:~n"),
            io:format("  Local port:  ~p~n", [LocalPort]),
            io:format("  Public addr: ~s:~p~n", [inet:ntoa(PubIP), PubPort]),

            %% Check if port is preserved
            if
                LocalPort =:= PubPort ->
                    io:format("  NAT type:    Port-preserving (good!)~n");
                true ->
                    io:format("  NAT type:    Port-changing (local ~p -> public ~p)~n",
                              [LocalPort, PubPort])
            end,

            %% Generate connection string
            ConnStr = lists:flatten(io_lib:format("~s:~p", [inet:ntoa(PubIP), PubPort])),
            io:format("~n>>> Connection string: ~s~n", [ConnStr]),
            io:format("~nSocket kept open! Now run:~n"),
            io:format("  pperl_diag:test_punch(Socket, \"<peer_conn_string>\").~n"),
            io:format("~nOr for quick test (new socket each time):~n"),
            io:format("  pperl_diag:test_punch(\"<peer_conn_string>\").~n~n"),

            {ok, Socket, ConnStr};
        {error, Reason} ->
            io:format("STUN failed: ~p~n", [Reason]),
            io:format("Check your internet connection.~n"),
            error
    end.

%% @doc Test hole punching with a peer using an existing socket from probe().
%% This is the CORRECT way - uses the same socket that generated your connection string.
-spec test_punch(gen_udp:socket(), string()) -> ok | {error, term()}.
test_punch(Socket, PeerConnStr) ->
    case parse_addr(PeerConnStr) of
        {ok, PeerIP, PeerPort} ->
            io:format("~n=== Hole Punch Test to ~s:~p ===~n~n",
                      [inet:ntoa(PeerIP), PeerPort]),

            %% Get info about our socket
            {ok, LocalPort} = inet:port(Socket),
            io:format("Using existing socket on local port ~p~n", [LocalPort]),
            io:format("~nStarting bidirectional test...~n"),
            io:format("(Run this on BOTH machines at the same time!)~n~n"),

            %% Set socket to active mode for receiving
            inet:setopts(Socket, [{active, true}]),

            %% Run test for 30 seconds
            run_punch_test(Socket, PeerIP, PeerPort, 30000),

            io:format("~nSocket still open - you can run test_punch again.~n"),
            ok;
        {error, Reason} ->
            io:format("Invalid connection string: ~p~n", [Reason]),
            {error, invalid_conn_str}
    end.

%% @doc Test hole punching with a NEW socket (quick test, may use different port!)
%% WARNING: This creates a new socket, so the port may differ from what you shared.
-spec test_punch(string()) -> ok | {error, term()}.
test_punch(PeerConnStr) ->
    case parse_addr(PeerConnStr) of
        {ok, PeerIP, PeerPort} ->
            io:format("~n=== Hole Punch Test to ~s:~p ===~n~n",
                      [inet:ntoa(PeerIP), PeerPort]),
            io:format("WARNING: Creating new socket - port may differ from probe()!~n"),
            io:format("         For accurate test, use: test_punch(Socket, PeerStr)~n~n"),

            %% Get our public address with new socket
            case stun_probe() of
                {ok, Socket, LocalPort, {OurIP, OurPort}} ->
                    io:format("This socket: ~s:~p (local port ~p)~n",
                              [inet:ntoa(OurIP), OurPort, LocalPort]),
                    io:format("~nStarting bidirectional test...~n"),
                    io:format("(Run this on BOTH machines at the same time!)~n~n"),

                    %% Set socket to active mode for receiving
                    inet:setopts(Socket, [{active, true}]),

                    %% Run test for 30 seconds
                    run_punch_test(Socket, PeerIP, PeerPort, 30000),

                    gen_udp:close(Socket),
                    ok;
                {error, Reason} ->
                    io:format("STUN failed: ~p~n", [Reason]),
                    {error, stun_failed}
            end;
        {error, Reason} ->
            io:format("Invalid connection string: ~p~n", [Reason]),
            {error, invalid_conn_str}
    end.

run_punch_test(Socket, PeerIP, PeerPort, Duration) ->
    EndTime = erlang:monotonic_time(millisecond) + Duration,
    run_punch_test_loop(Socket, PeerIP, PeerPort, EndTime, 0, 0, 0).

run_punch_test_loop(Socket, PeerIP, PeerPort, EndTime, Sent, Recv, LastRecv) ->
    Now = erlang:monotonic_time(millisecond),
    case Now < EndTime of
        true ->
            %% Send a packet
            SeqBin = integer_to_binary(Sent),
            Packet = <<"DIAG:", SeqBin/binary, ":", (integer_to_binary(Now))/binary>>,
            gen_udp:send(Socket, PeerIP, PeerPort, Packet),
            NewSent = Sent + 1,

            %% Check for received packets (non-blocking)
            {NewRecv, NewLastRecv} = drain_recv(Socket, Recv, LastRecv),

            %% Status update every 2 seconds
            case Sent rem 4 of
                0 ->
                    Remaining = (EndTime - Now) div 1000,
                    io:format("[~2.10.0Bs] Sent: ~p | Received: ~p~n",
                              [Remaining, NewSent, NewRecv]);
                _ -> ok
            end,

            timer:sleep(500),
            run_punch_test_loop(Socket, PeerIP, PeerPort, EndTime,
                                NewSent, NewRecv, NewLastRecv);
        false ->
            io:format("~n=== Test Complete ===~n"),
            io:format("Packets sent:     ~p~n", [Sent]),
            io:format("Packets received: ~p~n", [Recv]),
            if
                Recv > 0 ->
                    io:format("~nSUCCESS! Hole punching is working.~n"),
                    io:format("You should be able to transfer files.~n");
                true ->
                    io:format("~nFAILED! No packets received.~n"),
                    io:format("Possible issues:~n"),
                    io:format("  - Symmetric NAT on one or both sides~n"),
                    io:format("  - Firewall blocking UDP~n"),
                    io:format("  - Wrong peer address~n"),
                    io:format("  - Timing: make sure BOTH sides run test_punch simultaneously~n")
            end,
            ok
    end.

drain_recv(Socket, Count, LastSeq) ->
    receive
        {udp, Socket, FromIP, FromPort, <<"DIAG:", Rest/binary>>} ->
            case binary:split(Rest, <<":">>) of
                [SeqBin, TimeBin] ->
                    Seq = binary_to_integer(SeqBin),
                    SendTime = binary_to_integer(TimeBin),
                    Now = erlang:monotonic_time(millisecond),
                    Latency = Now - SendTime,
                    io:format("  << RECV #~p from ~s:~p (latency: ~pms)~n",
                              [Seq, inet:ntoa(FromIP), FromPort, Latency]),
                    drain_recv(Socket, Count + 1, Seq);
                _ ->
                    drain_recv(Socket, Count + 1, LastSeq)
            end;
        {udp, Socket, FromIP, FromPort, Data} ->
            io:format("  << RECV unknown from ~s:~p: ~p~n",
                      [inet:ntoa(FromIP), FromPort, Data]),
            drain_recv(Socket, Count + 1, LastSeq)
    after 0 ->
        {Count, LastSeq}
    end.

%%===================================================================
%% Lower Level Tools
%%===================================================================

%% @doc Get detailed STUN information from multiple servers.
-spec stun_info() -> ok.
stun_info() ->
    io:format("~n=== STUN Information ===~n~n"),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    {ok, LocalPort} = inet:port(Socket),
    io:format("Local port: ~p~n~n", [LocalPort]),

    lists:foreach(fun({Host, Port}) ->
        io:format("~s:~p -> ", [Host, Port]),
        case query_stun(Socket, Host, Port) of
            {ok, {IP, MappedPort}} ->
                io:format("~s:~p", [inet:ntoa(IP), MappedPort]),
                if MappedPort =:= LocalPort -> io:format(" (preserved)");
                   true -> io:format(" (changed)")
                end,
                io:format("~n");
            {error, Reason} ->
                io:format("ERROR: ~p~n", [Reason])
        end
    end, ?STUN_SERVERS),

    gen_udp:close(Socket),
    ok.

%% @doc Listen for raw UDP packets on a port.
-spec listen_raw(inet:port_number()) -> no_return().
listen_raw(Port) ->
    {ok, Socket} = gen_udp:open(Port, [binary, {active, true}]),
    io:format("Listening for UDP on port ~p...~n", [Port]),
    listen_raw_loop(Socket, 0).

listen_raw_loop(Socket, Count) ->
    receive
        {udp, Socket, FromIP, FromPort, Data} ->
            io:format("[~p] From ~s:~p: ~p (~p bytes)~n",
                      [Count, inet:ntoa(FromIP), FromPort, Data, byte_size(Data)]),
            listen_raw_loop(Socket, Count + 1)
    end.

%% @doc Send raw UDP packets to a destination.
-spec send_raw(string(), inet:port_number(), pos_integer()) -> ok.
send_raw(Host, Port, Count) ->
    {ok, Socket} = gen_udp:open(0, [binary]),
    {ok, LocalPort} = inet:port(Socket),
    io:format("Sending from port ~p to ~s:~p~n", [LocalPort, Host, Port]),
    send_raw_loop(Socket, Host, Port, Count, 0),
    gen_udp:close(Socket),
    ok.

send_raw_loop(_Socket, _Host, _Port, Max, Max) ->
    io:format("Done.~n");
send_raw_loop(Socket, Host, Port, Max, N) ->
    Packet = <<"TEST:", (integer_to_binary(N))/binary>>,
    gen_udp:send(Socket, Host, Port, Packet),
    io:format("Sent #~p~n", [N]),
    timer:sleep(500),
    send_raw_loop(Socket, Host, Port, Max, N + 1).

%%===================================================================
%% NAT Type Detection
%%===================================================================

%% @doc Detect NAT type (basic detection).
-spec nat_type() -> ok.
nat_type() ->
    io:format("~n=== NAT Type Detection ===~n~n"),

    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    {ok, LocalPort} = inet:port(Socket),
    io:format("Local port: ~p~n", [LocalPort]),

    %% Query two different STUN servers
    Results = lists:map(fun({Host, Port}) ->
        case query_stun(Socket, Host, Port) of
            {ok, Addr} -> {ok, Host, Addr};
            Error -> {error, Host, Error}
        end
    end, lists:sublist(?STUN_SERVERS, 2)),

    gen_udp:close(Socket),

    case Results of
        [{ok, _, {IP1, Port1}}, {ok, _, {IP2, Port2}}] ->
            io:format("~nServer 1: ~s:~p~n", [inet:ntoa(IP1), Port1]),
            io:format("Server 2: ~s:~p~n", [inet:ntoa(IP2), Port2]),

            if
                {IP1, Port1} =:= {IP2, Port2} ->
                    io:format("~nNAT Type: Full Cone or Restricted Cone~n"),
                    io:format("  -> Same mapping for different destinations~n"),
                    io:format("  -> Hole punching should work!~n");
                IP1 =:= IP2, Port1 =/= Port2 ->
                    io:format("~nNAT Type: Symmetric (Port-dependent)~n"),
                    io:format("  -> Different port for each destination~n"),
                    io:format("  -> Hole punching may fail with another symmetric NAT~n");
                true ->
                    io:format("~nNAT Type: Unknown/Complex~n"),
                    io:format("  -> Different IP mapping for different servers~n"),
                    io:format("  -> May have multiple NATs or load balancing~n")
            end;
        _ ->
            io:format("Could not complete NAT detection.~n"),
            lists:foreach(fun
                ({ok, H, A}) -> io:format("  ~s: ~p~n", [H, A]);
                ({error, H, E}) -> io:format("  ~s: ERROR ~p~n", [H, E])
            end, Results)
    end,
    ok.

%%===================================================================
%% Internal
%%===================================================================

stun_probe() ->
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    {ok, LocalPort} = inet:port(Socket),

    case query_stun_servers(Socket, ?STUN_SERVERS) of
        {ok, PublicAddr} ->
            {ok, Socket, LocalPort, PublicAddr};
        {error, _} = Err ->
            gen_udp:close(Socket),
            Err
    end.

query_stun_servers(_Socket, []) ->
    {error, no_stun_response};
query_stun_servers(Socket, [{Host, Port} | Rest]) ->
    case query_stun(Socket, Host, Port) of
        {ok, _} = Ok -> Ok;
        {error, _} -> query_stun_servers(Socket, Rest)
    end.

query_stun(Socket, Host, Port) ->
    {Request, TxnId} = stun_codec:binding_request(),
    case inet:getaddr(Host, inet) of
        {ok, IP} ->
            ok = gen_udp:send(Socket, IP, Port, Request),
            case gen_udp:recv(Socket, 0, 3000) of
                {ok, {_, _, Data}} ->
                    case stun_codec:decode(Data) of
                        {ok, #{class := success_response, txn_id := TxnId, attrs := Attrs}} ->
                            extract_mapped_address(Attrs);
                        _ ->
                            {error, invalid_response}
                    end;
                {error, timeout} ->
                    {error, timeout};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
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

parse_addr(Str) ->
    case string:split(Str, ":") of
        [IPStr, PortStr] ->
            case inet:parse_address(IPStr) of
                {ok, IP} ->
                    try
                        Port = list_to_integer(PortStr),
                        {ok, IP, Port}
                    catch _:_ ->
                        {error, invalid_port}
                    end;
                {error, _} ->
                    {error, invalid_ip}
            end;
        _ ->
            {error, invalid_format}
    end.
