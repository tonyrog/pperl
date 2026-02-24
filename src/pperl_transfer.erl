%%%-------------------------------------------------------------------
%%% @doc Resumable file transfer over DTLS.
%%%
%%% Features:
%%%   - Streaming (doesn't load whole file into memory)
%%%   - Resumable (can continue interrupted transfers)
%%%   - Verified (SHA256 checksum at end)
%%%
%%% Protocol:
%%%   OFFER  -> {offer, FileId, Filename, Size}
%%%   ACCEPT -> {accept, Offset}  (0 = new, >0 = resume)
%%%   DATA   -> {data, Offset, Chunk}
%%%   ACK    -> {ack, Offset}
%%%   DONE   -> {done, FinalHash}
%%%   ERROR  -> {error, Reason}
%%%
%%% Transfer state is persisted to allow resumption after disconnect.
%%%-------------------------------------------------------------------
-module(pperl_transfer).

-include_lib("kernel/include/file.hrl").

-export([
    send_file/3,
    send_file/4,
    recv_file/1,
    recv_file/2,
    list_pending/0,
    cancel_pending/1,
    test_local/0,
    test_local/1
]).

-define(CHUNK_SIZE, 1200).
-define(ACK_TIMEOUT, 5000).
-define(MAX_RETRIES, 3).
-define(STATE_DIR, ".pperl/transfers").

-record(transfer_state, {
    file_id,
    filename,
    size,
    offset,
    dest_path,
    hash_state
}).

%%===================================================================
%% Send API
%%===================================================================

-spec send_file(ssl:sslsocket(), string(), string()) -> ok | {error, term()}.
send_file(Socket, FilePath, DestName) ->
    send_file(Socket, FilePath, DestName, fun(_) -> ok end).

-spec send_file(ssl:sslsocket(), string(), string(), fun((map()) -> ok)) ->
    ok | {error, term()}.
send_file(Socket, FilePath, DestName, ProgressFun) ->
    case file:open(FilePath, [read, binary, raw]) of
        {ok, Fd} ->
            try
                {ok, #file_info{size = Size}} = file:read_file_info(FilePath),
                FileId = make_file_id(DestName, Size),

                %% Send offer
                ok = send_msg(Socket, {offer, FileId, DestName, Size}),

                %% Wait for accept with resume offset
                case recv_msg(Socket, ?ACK_TIMEOUT) of
                    {ok, {accept, Offset}} ->
                        ProgressFun(#{status => accepted, size => Size, offset => Offset}),
                        send_chunks(Socket, Fd, Size, Offset, ProgressFun);
                    {ok, {reject, Reason}} ->
                        {error, {rejected, Reason}};
                    {error, _} = Error ->
                        Error
                end
            after
                file:close(Fd)
            end;
        {error, Reason} ->
            {error, {open_file, Reason}}
    end.

send_chunks(Socket, Fd, Size, Offset, ProgressFun) ->
    %% Seek to resume position
    {ok, Offset} = file:position(Fd, Offset),

    %% Initialize hash - for resume we'd need to recompute from start
    %% For simplicity, we always hash from beginning on sender side
    HashState = init_hash_from_file(Fd, Offset),

    send_chunks_loop(Socket, Fd, Size, Offset, HashState, ProgressFun).

send_chunks_loop(Socket, Fd, Size, Offset, HashState, ProgressFun) when Offset < Size ->
    case file:read(Fd, ?CHUNK_SIZE) of
        {ok, Chunk} ->
            ChunkSize = byte_size(Chunk),
            NewHashState = crypto:hash_update(HashState, Chunk),

            case send_chunk_with_retry(Socket, Offset, Chunk, ?MAX_RETRIES) of
                ok ->
                    NewOffset = Offset + ChunkSize,
                    ProgressFun(#{status => sending, offset => NewOffset, size => Size}),
                    send_chunks_loop(Socket, Fd, Size, NewOffset, NewHashState, ProgressFun);
                {error, _} = Error ->
                    Error
            end;
        eof ->
            %% Shouldn't happen if Size is correct
            finish_send(Socket, HashState, ProgressFun);
        {error, Reason} ->
            {error, {read_file, Reason}}
    end;
send_chunks_loop(Socket, _Fd, _Size, _Offset, HashState, ProgressFun) ->
    finish_send(Socket, HashState, ProgressFun).

finish_send(Socket, HashState, ProgressFun) ->
    FinalHash = crypto:hash_final(HashState),
    ok = send_msg(Socket, {done, FinalHash}),

    case recv_msg(Socket, ?ACK_TIMEOUT) of
        {ok, {ack, done}} ->
            ProgressFun(#{status => complete}),
            ok;
        {ok, {error, Reason}} ->
            {error, {remote_error, Reason}};
        {error, _} = Error ->
            Error
    end.

send_chunk_with_retry(_Socket, _Offset, _Chunk, 0) ->
    {error, max_retries};
send_chunk_with_retry(Socket, Offset, Chunk, Retries) ->
    ok = send_msg(Socket, {data, Offset, Chunk}),
    NextOffset = Offset + byte_size(Chunk),

    case recv_msg(Socket, ?ACK_TIMEOUT) of
        {ok, {ack, NextOffset}} ->
            ok;
        {ok, {ack, _Other}} ->
            send_chunk_with_retry(Socket, Offset, Chunk, Retries - 1);
        {error, timeout} ->
            send_chunk_with_retry(Socket, Offset, Chunk, Retries - 1);
        {error, _} = Error ->
            Error
    end.

%% Hash file from start up to Offset (for resume case)
init_hash_from_file(Fd, 0) ->
    {ok, 0} = file:position(Fd, 0),
    crypto:hash_init(sha256);
init_hash_from_file(Fd, Offset) ->
    {ok, 0} = file:position(Fd, 0),
    HashState = crypto:hash_init(sha256),
    hash_file_range(Fd, HashState, Offset).

hash_file_range(_Fd, HashState, 0) ->
    HashState;
hash_file_range(Fd, HashState, Remaining) ->
    ToRead = min(?CHUNK_SIZE, Remaining),
    {ok, Data} = file:read(Fd, ToRead),
    NewHashState = crypto:hash_update(HashState, Data),
    hash_file_range(Fd, NewHashState, Remaining - byte_size(Data)).

%%===================================================================
%% Receive API
%%===================================================================

-spec recv_file(ssl:sslsocket()) -> {ok, string()} | {error, term()}.
recv_file(Socket) ->
    recv_file(Socket, ".").

-spec recv_file(ssl:sslsocket(), string()) -> {ok, string()} | {error, term()}.
recv_file(Socket, DestDir) ->
    case recv_msg(Socket, 30000) of
        {ok, {offer, FileId, Filename, Size}} ->
            io:format("Offered: ~s (~p bytes)~n", [Filename, Size]),

            %% Check for existing partial transfer
            State = load_or_create_state(FileId, Filename, Size, DestDir),

            io:format("Resuming from offset ~p~n", [State#transfer_state.offset]),
            ok = send_msg(Socket, {accept, State#transfer_state.offset}),

            recv_chunks(Socket, State);
        {error, _} = Error ->
            Error
    end.

recv_chunks(Socket, State) ->
    #transfer_state{dest_path = DestPath, offset = Offset} = State,

    %% Open file - append if resuming, write if new
    Mode = case Offset of
        0 -> [write, binary, raw];
        _ -> [write, binary, raw, append]
    end,
    {ok, Fd} = file:open(DestPath, Mode),

    try
        recv_chunks_loop(Socket, Fd, State)
    after
        file:close(Fd)
    end.

recv_chunks_loop(Socket, Fd, State) ->
    #transfer_state{size = Size, offset = Offset,
                    hash_state = HashState} = State,

    case recv_msg(Socket, 30000) of
        {ok, {data, Offset, Chunk}} ->
            %% Write chunk
            ok = file:write(Fd, Chunk),
            ChunkSize = byte_size(Chunk),
            NewOffset = Offset + ChunkSize,
            NewHashState = crypto:hash_update(HashState, Chunk),

            %% ACK with next expected offset
            ok = send_msg(Socket, {ack, NewOffset}),

            %% Update and persist state
            NewState = State#transfer_state{offset = NewOffset, hash_state = NewHashState},
            save_state(NewState),

            io:format("\rReceived: ~p / ~p bytes", [NewOffset, Size]),
            recv_chunks_loop(Socket, Fd, NewState);

        {ok, {data, _OtherOffset, _Chunk}} ->
            %% Out of order or duplicate, re-ack current position
            ok = send_msg(Socket, {ack, Offset}),
            recv_chunks_loop(Socket, Fd, State);

        {ok, {done, ExpectedHash}} ->
            io:format("~n"),
            verify_and_finish(Socket, State, ExpectedHash);

        {error, _} = Error ->
            Error
    end.

verify_and_finish(Socket, State, ExpectedHash) ->
    #transfer_state{file_id = FileId, dest_path = DestPath, hash_state = HashState} = State,

    ActualHash = crypto:hash_final(HashState),

    if ActualHash == ExpectedHash ->
            delete_state(FileId),
            ok = send_msg(Socket, {ack, done}),
            {ok, DestPath};
       true ->
            ok = send_msg(Socket, {error, checksum_mismatch}),
            {error, checksum_mismatch}
    end.

%%===================================================================
%% State Persistence
%%===================================================================

state_dir() ->
    filename:join(os:getenv("HOME"), ?STATE_DIR).

state_file(FileId) ->
    filename:join(state_dir(), binary_to_list(base64:encode(FileId)) ++ ".state").

make_file_id(Filename, Size) ->
    crypto:hash(sha256, [Filename, integer_to_binary(Size)]).

load_or_create_state(FileId, Filename, Size, DestDir) ->
    StateFile = state_file(FileId),
    case file:read_file(StateFile) of
        {ok, Bin} ->
            State = binary_to_term(Bin),
            %% Recompute hash from existing partial file
            recompute_hash_state(State);
        {error, enoent} ->
            %% New transfer
            filelib:ensure_dir(StateFile),
            DestPath = filename:join(DestDir, Filename),
            %% Remove any existing file
            file:delete(DestPath),
            State = #transfer_state{
                file_id = FileId,
                filename = Filename,
                size = Size,
                offset = 0,
                dest_path = DestPath,
                hash_state = crypto:hash_init(sha256)
            },
            save_state(State),
            State
    end.

recompute_hash_state(State) ->
    #transfer_state{dest_path = DestPath, offset = Offset} = State,
    HashState = case Offset of
        0 ->
            crypto:hash_init(sha256);
        _ ->
            case file:open(DestPath, [read, binary, raw]) of
                {ok, Fd} ->
                    try
                        hash_file_to_offset(Fd, Offset)
                    after
                        file:close(Fd)
                    end;
                {error, _} ->
                    %% File gone, start over
                    crypto:hash_init(sha256)
            end
    end,
    State#transfer_state{hash_state = HashState}.

hash_file_to_offset(Fd, Offset) ->
    hash_file_range(Fd, crypto:hash_init(sha256), Offset).

save_state(State) ->
    %% Don't persist hash_state - we recompute it on load
    StateToSave = State#transfer_state{hash_state = undefined},
    StateFile = state_file(State#transfer_state.file_id),
    filelib:ensure_dir(StateFile),
    file:write_file(StateFile, term_to_binary(StateToSave)).

delete_state(FileId) ->
    file:delete(state_file(FileId)).

-spec list_pending() -> [map()].
list_pending() ->
    case file:list_dir(state_dir()) of
        {ok, Files} ->
            lists:filtermap(fun(F) ->
                case filename:extension(F) of
                    ".state" ->
                        Path = filename:join(state_dir(), F),
                        case file:read_file(Path) of
                            {ok, Bin} ->
                                #transfer_state{filename = Name, size = Size, offset = Off} =
                                    binary_to_term(Bin),
                                {true, #{filename => Name, size => Size, received => Off}};
                            _ ->
                                false
                        end;
                    _ ->
                        false
                end
            end, Files);
        {error, _} ->
            []
    end.

-spec cancel_pending(string()) -> ok | {error, not_found}.
cancel_pending(Filename) ->
    case file:list_dir(state_dir()) of
        {ok, Files} ->
            Found = lists:any(fun(F) ->
                Path = filename:join(state_dir(), F),
                case file:read_file(Path) of
                    {ok, Bin} ->
                        #transfer_state{filename = Name, dest_path = DestPath} =
                            binary_to_term(Bin),
                        case Name == Filename of
                            true ->
                                file:delete(Path),
                                file:delete(DestPath),
                                true;
                            false ->
                                false
                        end;
                    _ ->
                        false
                end
            end, Files),
            case Found of
                true -> ok;
                false -> {error, not_found}
            end;
        {error, _} ->
            {error, not_found}
    end.

%%===================================================================
%% Internal
%%===================================================================

send_msg(Socket, Term) ->
    ssl:send(Socket, term_to_binary(Term)).

recv_msg(Socket, Timeout) ->
    case ssl:recv(Socket, 0, Timeout) of
        {ok, Data} ->
            {ok, binary_to_term(Data)};
        {error, _} = Error ->
            Error
    end.

%%===================================================================
%% Testing
%%===================================================================

test_local() ->
    test_local("/etc/passwd").

test_local(FilePath) ->
    Port = 9998,
    DestDir = "/tmp",

    %% Ensure we trust ourselves
    case pperl_identity:list_peers() of
        [] ->
            {ok, #{cert := CertPath}} = pperl_identity:get_identity(),
            pperl_identity:import_peer("myself", CertPath);
        _ ->
            ok
    end,

    Self = self(),
    spawn(fun() ->
        {ok, ListenSocket} = pperl_dtls:listen(Port),
        io:format("[Receiver] Listening~n"),
        case pperl_dtls:accept(ListenSocket) of
            {ok, Socket} ->
                Result = recv_file(Socket, DestDir),
                io:format("[Receiver] Result: ~p~n", [Result]),
                Self ! {receiver_done, Result},
                pperl_dtls:close(Socket);
            {error, Reason} ->
                Self ! {receiver_done, {error, Reason}}
        end
    end),

    timer:sleep(100),

    io:format("[Sender] Connecting~n"),
    case pperl_dtls:connect("localhost", Port) of
        {ok, Socket} ->
            Basename = filename:basename(FilePath),
            Result = send_file(Socket, FilePath, Basename, fun(P) ->
                io:format("[Sender] ~p~n", [P])
            end),
            io:format("[Sender] Result: ~p~n", [Result]),
            pperl_dtls:close(Socket);
        {error, Reason} ->
            io:format("[Sender] Connect error: ~p~n", [Reason])
    end,

    receive
        {receiver_done, R} -> R
    after 30000 ->
        {error, timeout}
    end.
