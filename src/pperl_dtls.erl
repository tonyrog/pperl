%%%-------------------------------------------------------------------
%%% @doc Simple DTLS server/client for testing encrypted P2P connections.
%%%-------------------------------------------------------------------
-module(pperl_dtls).

-export([
    %% Server
    listen/1,
    listen/2,
    accept/1,

    %% Client
    connect/2,
    connect/3,
    connect/4,

    %% Data transfer
    send/2,
    recv/1,
    recv/2,

    %% Control
    close/1,

    %% Testing helpers
    echo_server/1,
    test_local/0,
    test_local/1
]).

-define(DEFAULT_TIMEOUT, 5000).

%%-------------------------------------------------------------------
%% Server API
%%-------------------------------------------------------------------

%% @doc Start listening on a UDP port for DTLS connections.
-spec listen(Port :: inet:port_number()) -> {ok, ssl:sslsocket()} | {error, term()}.
listen(Port) ->
    listen(Port, true).

-spec listen(Port :: inet:port_number(), Verify :: boolean()) -> {ok, ssl:sslsocket()} | {error, term()}.
listen(Port, Verify) ->
    application:ensure_all_started(ssl),
    BaseOpts = pperl_identity:ssl_options(server, Verify),
    ListenOpts = BaseOpts ++ [
        {reuseaddr, true},
        {active, false},
        {mode, binary}
    ],
    ssl:listen(Port, ListenOpts).

%% @doc Accept an incoming DTLS connection.
-spec accept(ListenSocket :: ssl:sslsocket()) -> {ok, ssl:sslsocket()} | {error, term()}.
accept(ListenSocket) ->
    case ssl:transport_accept(ListenSocket) of
        {ok, Socket} ->
            case ssl:handshake(Socket, ?DEFAULT_TIMEOUT) of
                {ok, SSLSocket} -> {ok, SSLSocket};
                {error, _} = Error -> Error
            end;
        {error, _} = Error ->
            Error
    end.

%%-------------------------------------------------------------------
%% Client API
%%-------------------------------------------------------------------

%% @doc Connect to a DTLS server.
-spec connect(Host :: inet:hostname(), Port :: inet:port_number()) ->
    {ok, ssl:sslsocket()} | {error, term()}.
connect(Host, Port) ->
    connect(Host, Port, ?DEFAULT_TIMEOUT).

-spec connect(Host :: inet:hostname(), Port :: inet:port_number(), Timeout :: timeout()) ->
    {ok, ssl:sslsocket()} | {error, term()}.
connect(Host, Port, Timeout) ->
    connect(Host, Port, Timeout, true).

-spec connect(Host :: inet:hostname(), Port :: inet:port_number(), Timeout :: timeout(), Verify :: boolean()) ->
    {ok, ssl:sslsocket()} | {error, term()}.
connect(Host, Port, Timeout, Verify) ->
    application:ensure_all_started(ssl),
    BaseOpts = pperl_identity:ssl_options(client, Verify),
    ConnectOpts = BaseOpts ++ [
        {active, false},
        {mode, binary}
    ],
    ssl:connect(Host, Port, ConnectOpts, Timeout).

%%-------------------------------------------------------------------
%% Data Transfer
%%-------------------------------------------------------------------

%% @doc Send data over DTLS connection.
-spec send(Socket :: ssl:sslsocket(), Data :: iodata()) -> ok | {error, term()}.
send(Socket, Data) ->
    ssl:send(Socket, Data).

%% @doc Receive data from DTLS connection.
-spec recv(Socket :: ssl:sslsocket()) -> {ok, binary()} | {error, term()}.
recv(Socket) ->
    recv(Socket, ?DEFAULT_TIMEOUT).

-spec recv(Socket :: ssl:sslsocket(), Timeout :: timeout()) -> {ok, binary()} | {error, term()}.
recv(Socket, Timeout) ->
    ssl:recv(Socket, 0, Timeout).

%% @doc Close DTLS connection.
-spec close(Socket :: ssl:sslsocket()) -> ok.
close(Socket) ->
    ssl:close(Socket).

%%-------------------------------------------------------------------
%% Testing Helpers
%%-------------------------------------------------------------------

%% @doc Start a simple echo server on given port.
-spec echo_server(Port :: inet:port_number()) -> no_return().
echo_server(Port) ->
    {ok, ListenSocket} = listen(Port),
    io:format("Echo server listening on port ~p~n", [Port]),
    echo_server_loop(ListenSocket).

echo_server_loop(ListenSocket) ->
    io:format("Waiting for connection...~n"),
    case accept(ListenSocket) of
        {ok, Socket} ->
            io:format("Client connected!~n"),
            spawn(fun() -> echo_handler(Socket) end),
            echo_server_loop(ListenSocket);
        {error, Reason} ->
            io:format("Accept error: ~p~n", [Reason]),
            echo_server_loop(ListenSocket)
    end.

echo_handler(Socket) ->
    case recv(Socket, 30000) of
        {ok, Data} ->
            io:format("Received: ~p~n", [Data]),
            ok = send(Socket, <<"ECHO: ", Data/binary>>),
            echo_handler(Socket);
        {error, closed} ->
            io:format("Client disconnected~n"),
            ok;
        {error, Reason} ->
            io:format("Recv error: ~p~n", [Reason]),
            close(Socket)
    end.

%% @doc Test DTLS locally - needs two terminals or processes.
%% Run test_local() which starts server and client in separate processes.
-spec test_local() -> ok.
test_local() ->
    test_local(false).  % Default to no verification for basic testing

-spec test_local(Verify :: boolean()) -> ok.
test_local(Verify) ->
    Port = 9999,

    %% Start server in background
    ServerPid = spawn(fun() ->
        {ok, ListenSocket} = listen(Port, Verify),
        io:format("[Server] Listening on ~p~n", [Port]),
        case accept(ListenSocket) of
            {ok, Socket} ->
                io:format("[Server] Client connected~n"),
                case recv(Socket, 10000) of
                    {ok, Data} ->
                        io:format("[Server] Received: ~s~n", [Data]),
                        send(Socket, <<"Hello from server!">>),
                        close(Socket);
                    {error, Reason} ->
                        io:format("[Server] Recv error: ~p~n", [Reason])
                end;
            {error, Reason} ->
                io:format("[Server] Accept error: ~p~n", [Reason])
        end
    end),

    %% Give server time to start
    timer:sleep(100),

    %% Connect as client
    io:format("[Client] Connecting to localhost:~p~n", [Port]),
    case connect("localhost", Port, ?DEFAULT_TIMEOUT, Verify) of
        {ok, Socket} ->
            io:format("[Client] Connected!~n"),
            ok = send(Socket, <<"Hello from client!">>),
            case recv(Socket, 5000) of
                {ok, Response} ->
                    io:format("[Client] Server replied: ~s~n", [Response]);
                {error, Reason} ->
                    io:format("[Client] Recv error: ~p~n", [Reason])
            end,
            close(Socket);
        {error, Reason} ->
            io:format("[Client] Connect error: ~p~n", [Reason])
    end,

    %% Clean up
    exit(ServerPid, normal),
    ok.
