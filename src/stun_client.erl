%%%-------------------------------------------------------------------
%%% @doc Simple STUN Client
%%%
%%% Query STUN servers to discover public IP and port.
%%% @end
%%%-------------------------------------------------------------------
-module(stun_client).

-export([get_mapped_address/0, get_mapped_address/1, get_mapped_address/2]).
-export([query/2, query/3]).

%% Default public STUN servers
-define(DEFAULT_SERVERS, [
    {"stun.l.google.com", 19302},
    {"stun1.l.google.com", 19302},
    {"stun.cloudflare.com", 3478}
]).

-define(DEFAULT_TIMEOUT, 3000).

%%--------------------------------------------------------------------
%% @doc Get mapped address from first responding default server
%% @end
%%--------------------------------------------------------------------
-spec get_mapped_address() -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
get_mapped_address() ->
    get_mapped_address(?DEFAULT_SERVERS).

-spec get_mapped_address([{string(), inet:port_number()}]) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
get_mapped_address([]) ->
    {error, no_servers_responded};
get_mapped_address([{Host, Port} | Rest]) ->
    case query(Host, Port) of
        {ok, Addr} -> {ok, Addr};
        {error, _} -> get_mapped_address(Rest)
    end.

-spec get_mapped_address(string(), inet:port_number()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
get_mapped_address(Host, Port) ->
    query(Host, Port).

%%--------------------------------------------------------------------
%% @doc Query a STUN server and return the mapped address
%% @end
%%--------------------------------------------------------------------
-spec query(string(), inet:port_number()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
query(Host, Port) ->
    query(Host, Port, ?DEFAULT_TIMEOUT).

-spec query(string(), inet:port_number(), timeout()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
query(Host, Port, Timeout) ->
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, Socket} ->
            Result = do_query(Socket, Host, Port, Timeout),
            gen_udp:close(Socket),
            Result;
        {error, _} = Err ->
            Err
    end.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------
do_query(Socket, Host, Port, Timeout) ->
    {Request, TxnId} = stun_codec:binding_request(),
    case resolve_host(Host) of
        {ok, IP} ->
            ok = gen_udp:send(Socket, IP, Port, Request),
            receive_response(Socket, TxnId, Timeout);
        {error, _} = Err ->
            Err
    end.

resolve_host(Host) when is_tuple(Host) ->
    {ok, Host};
resolve_host(Host) ->
    inet:getaddr(Host, inet).

receive_response(Socket, TxnId, Timeout) ->
    case gen_udp:recv(Socket, 0, Timeout) of
        {ok, {_IP, _Port, Data}} ->
            case stun_codec:decode(Data) of
                {ok, #{class := success_response, txn_id := TxnId, attrs := Attrs}} ->
                    extract_mapped_address(Attrs);
                {ok, #{class := error_response, attrs := Attrs}} ->
                    case lists:keyfind(error_code, 1, Attrs) of
                        {error_code, {Code, Reason}} ->
                            {error, {stun_error, Code, Reason}};
                        false ->
                            {error, stun_error_unknown}
                    end;
                {ok, #{txn_id := OtherTxn}} when OtherTxn =/= TxnId ->
                    %% Wrong transaction, keep waiting
                    receive_response(Socket, TxnId, Timeout);
                {error, _} = Err ->
                    Err
            end;
        {error, timeout} ->
            {error, timeout};
        {error, _} = Err ->
            Err
    end.

extract_mapped_address(Attrs) ->
    %% Prefer XOR-MAPPED-ADDRESS (more NAT-friendly)
    case lists:keyfind(xor_mapped_address, 1, Attrs) of
        {xor_mapped_address, Addr} ->
            {ok, Addr};
        false ->
            case lists:keyfind(mapped_address, 1, Attrs) of
                {mapped_address, Addr} ->
                    {ok, Addr};
                false ->
                    {error, no_mapped_address}
            end
    end.
