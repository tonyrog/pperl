%%%-------------------------------------------------------------------
%%% @doc STUN Server (RFC 5389)
%%%
%%% Simple STUN server that responds to Binding Requests with the
%%% client's reflexive transport address.
%%% @end
%%%-------------------------------------------------------------------
-module(stun_server).
-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1, stop/1]).
-export([start/0, start/1]).  % For quick testing

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    socket :: gen_udp:socket(),
    port   :: inet:port_number(),
    stats  :: #{requests => non_neg_integer()}
}).

-define(DEFAULT_PORT, 3478).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start server (not linked) for quick testing
-spec start() -> {ok, pid()} | {error, term()}.
start() ->
    start(?DEFAULT_PORT).

-spec start(inet:port_number()) -> {ok, pid()} | {error, term()}.
start(Port) ->
    gen_server:start(?MODULE, [Port], []).

%% @doc Start linked server
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link(?DEFAULT_PORT).

-spec start_link(inet:port_number()) -> {ok, pid()} | {error, term()}.
start_link(Port) ->
    gen_server:start_link(?MODULE, [Port], []).

%% @doc Stop the server
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------

init([Port]) ->
    case gen_udp:open(Port, [binary, {active, true}, {reuseaddr, true}]) of
        {ok, Socket} ->
            {ok, ActualPort} = inet:port(Socket),
            io:format("STUN server listening on port ~p~n", [ActualPort]),
            {ok, #state{socket = Socket,
                        port = ActualPort,
                        stats = #{requests => 0}}};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(stats, _From, #state{stats = Stats} = State) ->
    {reply, Stats, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, IP, Port, Data}, #state{socket = Socket, stats = Stats} = State) ->
    NewStats = handle_stun_packet(Socket, IP, Port, Data, Stats),
    {noreply, State#state{stats = NewStats}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{socket = Socket}) ->
    gen_udp:close(Socket),
    ok.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

handle_stun_packet(Socket, IP, Port, Data, Stats) ->
    case stun_codec:decode(Data) of
        {ok, #{class := request, method := binding, txn_id := TxnId}} ->
            send_binding_response(Socket, IP, Port, TxnId),
            maps:update_with(requests, fun(N) -> N + 1 end, Stats);
        {ok, _Other} ->
            %% Ignore non-binding-request messages
            Stats;
        {error, _Reason} ->
            %% Ignore malformed packets
            Stats
    end.

send_binding_response(Socket, IP, Port, TxnId) ->
    Attrs = [
        {xor_mapped_address, {IP, Port}},
        {software, "pperl-stun/0.1"}
    ],
    Response = stun_codec:encode(
        #{class => success_response, method => binding, txn_id => TxnId},
        Attrs
    ),
    gen_udp:send(Socket, IP, Port, Response).
