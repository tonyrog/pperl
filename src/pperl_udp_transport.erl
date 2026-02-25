%%%-------------------------------------------------------------------
%%% @doc Custom UDP transport for DTLS that supports pre-punched sockets.
%%%
%%% This module allows reusing an existing UDP socket (that has already
%%% done STUN and hole punching) for DTLS connections, instead of
%%% opening a new socket.
%%%
%%% Usage:
%%%   1. Open and punch a socket: pperl_udp_transport:prepare(Socket, Port)
%%%   2. Use cb_info option: {cb_info, {pperl_udp_transport, udp, udp_closed, udp_error}}
%%%   3. ssl:connect or ssl:listen will use the prepared socket
%%%
%%% The prepared socket is stored in ETS and retrieved when open/2 is
%%% called with the matching port.
%%%-------------------------------------------------------------------
-module(pperl_udp_transport).

-export([
    %% Setup
    init/0,
    prepare/2,
    unprepare/1,

    %% Transport callbacks (used by ssl via cb_info)
    open/2,
    controlling_process/2,
    setopts/2,
    getopts/2,
    port/1,
    peername/1,
    sockname/1,
    send/4,
    recv/3,
    close/1
]).

-define(TABLE, pperl_udp_transport_sockets).

%%-------------------------------------------------------------------
%% Setup API
%%-------------------------------------------------------------------

%% @doc Initialize the transport (creates ETS table).
%% Call once at application start.
-spec init() -> ok.
init() ->
    case ets:whereis(?TABLE) of
        undefined ->
            ?TABLE = ets:new(?TABLE, [named_table, public, set]),
            ok;
        _ ->
            ok
    end.

%% @doc Register a pre-punched socket for a specific port.
%% When ssl calls open/2 with this port, it will get this socket.
-spec prepare(gen_udp:socket(), inet:port_number()) -> ok.
prepare(Socket, Port) ->
    init(),
    ets:insert(?TABLE, {Port, Socket}),
    ok.

%% @doc Remove a prepared socket.
-spec unprepare(inet:port_number()) -> ok.
unprepare(Port) ->
    catch ets:delete(?TABLE, Port),
    ok.

%%-------------------------------------------------------------------
%% Transport callbacks
%%-------------------------------------------------------------------

%% @doc Open a UDP socket, or return a pre-prepared one.
-spec open(inet:port_number(), list()) -> {ok, gen_udp:socket()} | {error, term()}.
open(Port, Opts) ->
    init(),
    case ets:lookup(?TABLE, Port) of
        [{Port, Socket}] ->
            %% Return the pre-punched socket
            %% Remove from table so it's not reused accidentally
            ets:delete(?TABLE, Port),
            %% Apply any options the caller wants
            apply_opts(Socket, Opts),
            {ok, Socket};
        [] ->
            %% No prepared socket, open a new one
            gen_udp:open(Port, Opts)
    end.

%% Apply socket options, filtering out ones we handle specially
apply_opts(Socket, Opts) ->
    %% Filter out options that don't apply to setopts
    SetOpts = lists:filter(fun
        ({ip, _}) -> false;
        ({ifaddr, _}) -> false;
        ({port, _}) -> false;
        ({fd, _}) -> false;
        (_) -> true
    end, Opts),
    case SetOpts of
        [] -> ok;
        _ -> inet:setopts(Socket, SetOpts)
    end.

-spec controlling_process(gen_udp:socket(), pid()) -> ok | {error, term()}.
controlling_process(Socket, Pid) ->
    gen_udp:controlling_process(Socket, Pid).

-spec setopts(gen_udp:socket(), list()) -> ok | {error, term()}.
setopts(Socket, Opts) ->
    inet:setopts(Socket, Opts).

-spec getopts(gen_udp:socket(), list()) -> {ok, list()} | {error, term()}.
getopts(Socket, Opts) ->
    inet:getopts(Socket, Opts).

-spec port(gen_udp:socket()) -> {ok, inet:port_number()} | {error, term()}.
port(Socket) ->
    inet:port(Socket).

-spec peername(gen_udp:socket()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
peername(Socket) ->
    inet:peername(Socket).

-spec sockname(gen_udp:socket()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
sockname(Socket) ->
    inet:sockname(Socket).

-spec send(gen_udp:socket(), inet:ip_address() | inet:hostname(), inet:port_number(), iodata()) ->
    ok | {error, term()}.
send(Socket, Host, Port, Packet) ->
    gen_udp:send(Socket, Host, Port, Packet).

-spec recv(gen_udp:socket(), non_neg_integer(), timeout()) ->
    {ok, {inet:ip_address(), inet:port_number(), binary()}} | {error, term()}.
recv(Socket, Length, Timeout) ->
    gen_udp:recv(Socket, Length, Timeout).

-spec close(gen_udp:socket()) -> ok.
close(Socket) ->
    gen_udp:close(Socket).
