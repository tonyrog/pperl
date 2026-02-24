%%%-------------------------------------------------------------------
%%% @doc STUN Protocol Codec (RFC 5389)
%%%
%%% Encodes and decodes STUN messages for NAT traversal.
%%% @end
%%%-------------------------------------------------------------------
-module(stun_codec).

-export([encode/1, encode/2, decode/1]).
-export([binding_request/0, binding_request/1]).
-export([transaction_id/0]).

%% STUN Magic Cookie (RFC 5389)
-define(MAGIC_COOKIE, 16#2112A442).

%% Message Classes (2 bits spread across type field)
-define(CLASS_REQUEST,         2#00).
-define(CLASS_INDICATION,      2#01).
-define(CLASS_SUCCESS_RESPONSE,2#10).
-define(CLASS_ERROR_RESPONSE,  2#11).

%% Message Methods
-define(METHOD_BINDING, 16#001).

%% Attribute Types
-define(ATTR_MAPPED_ADDRESS,     16#0001).
-define(ATTR_USERNAME,           16#0006).
-define(ATTR_MESSAGE_INTEGRITY,  16#0008).
-define(ATTR_ERROR_CODE,         16#0009).
-define(ATTR_UNKNOWN_ATTRIBUTES, 16#000A).
-define(ATTR_REALM,              16#0014).
-define(ATTR_NONCE,              16#0015).
-define(ATTR_XOR_MAPPED_ADDRESS, 16#0020).
-define(ATTR_SOFTWARE,           16#8022).
-define(ATTR_FINGERPRINT,        16#8028).

%% Address Families
-define(FAMILY_IPV4, 16#01).
-define(FAMILY_IPV6, 16#02).

%%--------------------------------------------------------------------
%% @doc Generate a random 96-bit transaction ID
%% @end
%%--------------------------------------------------------------------
-spec transaction_id() -> binary().
transaction_id() ->
    crypto:strong_rand_bytes(12).

%%--------------------------------------------------------------------
%% @doc Create a STUN Binding Request with new transaction ID
%% @end
%%--------------------------------------------------------------------
-spec binding_request() -> {binary(), TxnId :: binary()}.
binding_request() ->
    TxnId = transaction_id(),
    {binding_request(TxnId), TxnId}.

%%--------------------------------------------------------------------
%% @doc Create a STUN Binding Request with specific transaction ID
%% @end
%%--------------------------------------------------------------------
-spec binding_request(TxnId :: binary()) -> binary().
binding_request(TxnId) when byte_size(TxnId) =:= 12 ->
    encode(#{class => request, method => binding, txn_id => TxnId}).

%%--------------------------------------------------------------------
%% @doc Encode a STUN message
%% @end
%%--------------------------------------------------------------------
-spec encode(map()) -> binary().
encode(Msg) ->
    encode(Msg, []).

-spec encode(map(), [tuple()]) -> binary().
encode(#{class := Class, method := Method, txn_id := TxnId}, Attrs) ->
    TypeInt = encode_type(Class, Method),
    AttrsData = encode_attributes(Attrs, TxnId),
    Length = byte_size(AttrsData),
    <<TypeInt:16, Length:16, ?MAGIC_COOKIE:32, TxnId:12/binary, AttrsData/binary>>.

%%--------------------------------------------------------------------
%% @doc Decode a STUN message
%% @end
%%--------------------------------------------------------------------
-spec decode(binary()) -> {ok, map()} | {error, term()}.
decode(<<TypeInt:16, Length:16, ?MAGIC_COOKIE:32, TxnId:12/binary, Rest/binary>>)
  when byte_size(Rest) >= Length ->
    <<AttrsData:Length/binary, _/binary>> = Rest,
    case decode_type(TypeInt) of
        {ok, Class, Method} ->
            Attrs = decode_attributes(AttrsData, TxnId),
            {ok, #{class => Class,
                   method => Method,
                   txn_id => TxnId,
                   attrs => Attrs}};
        {error, _} = Err ->
            Err
    end;
decode(<<_:16, _:16, BadCookie:32, _/binary>>) when BadCookie =/= ?MAGIC_COOKIE ->
    {error, {bad_magic_cookie, BadCookie}};
decode(Data) when byte_size(Data) < 20 ->
    {error, {incomplete, need_more_data}};
decode(_) ->
    {error, invalid_stun_message}.

%%--------------------------------------------------------------------
%% Internal: Encode message type from class and method
%%--------------------------------------------------------------------
encode_type(Class, Method) ->
    %% RFC 5389: Type field encoding
    %% Bits: M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
    ClassInt = class_to_int(Class),
    MethodInt = method_to_int(Method),
    C0 = ClassInt band 1,
    C1 = (ClassInt bsr 1) band 1,
    M0_3 = MethodInt band 16#F,
    M4_6 = (MethodInt bsr 4) band 16#7,
    M7_11 = (MethodInt bsr 7) band 16#1F,
    (M7_11 bsl 9) bor (C1 bsl 8) bor (M4_6 bsl 5) bor (C0 bsl 4) bor M0_3.

class_to_int(request)          -> ?CLASS_REQUEST;
class_to_int(indication)       -> ?CLASS_INDICATION;
class_to_int(success_response) -> ?CLASS_SUCCESS_RESPONSE;
class_to_int(error_response)   -> ?CLASS_ERROR_RESPONSE.

method_to_int(binding) -> ?METHOD_BINDING.

%%--------------------------------------------------------------------
%% Internal: Decode message type to class and method
%%--------------------------------------------------------------------
decode_type(TypeInt) ->
    %% Extract class bits (C0 at bit 4, C1 at bit 8)
    C0 = (TypeInt bsr 4) band 1,
    C1 = (TypeInt bsr 8) band 1,
    ClassInt = (C1 bsl 1) bor C0,
    %% Extract method bits
    M0_3 = TypeInt band 16#F,
    M4_6 = (TypeInt bsr 5) band 16#7,
    M7_11 = (TypeInt bsr 9) band 16#1F,
    MethodInt = (M7_11 bsl 7) bor (M4_6 bsl 4) bor M0_3,
    case {int_to_class(ClassInt), int_to_method(MethodInt)} of
        {{ok, Class}, {ok, Method}} -> {ok, Class, Method};
        {{error, _} = E, _} -> E;
        {_, {error, _} = E} -> E
    end.

int_to_class(?CLASS_REQUEST)          -> {ok, request};
int_to_class(?CLASS_INDICATION)       -> {ok, indication};
int_to_class(?CLASS_SUCCESS_RESPONSE) -> {ok, success_response};
int_to_class(?CLASS_ERROR_RESPONSE)   -> {ok, error_response};
int_to_class(C)                       -> {error, {unknown_class, C}}.

int_to_method(?METHOD_BINDING) -> {ok, binding};
int_to_method(M)               -> {error, {unknown_method, M}}.

%%--------------------------------------------------------------------
%% Internal: Encode attributes
%%--------------------------------------------------------------------
encode_attributes(Attrs, TxnId) ->
    iolist_to_binary([encode_attribute(A, TxnId) || A <- Attrs]).

encode_attribute({mapped_address, {IP, Port}}, _TxnId) ->
    encode_address_attr(?ATTR_MAPPED_ADDRESS, IP, Port);
encode_attribute({xor_mapped_address, {IP, Port}}, TxnId) ->
    encode_xor_address_attr(?ATTR_XOR_MAPPED_ADDRESS, IP, Port, TxnId);
encode_attribute({software, Str}, _TxnId) ->
    encode_string_attr(?ATTR_SOFTWARE, Str);
encode_attribute({error_code, {Code, Reason}}, _TxnId) ->
    encode_error_code(Code, Reason);
encode_attribute({Type, Value}, _TxnId) when is_integer(Type), is_binary(Value) ->
    %% Raw attribute
    Padded = pad4(Value),
    <<Type:16, (byte_size(Value)):16, Padded/binary>>.

encode_address_attr(Type, {A, B, C, D}, Port) ->
    Value = <<0, ?FAMILY_IPV4, Port:16, A, B, C, D>>,
    <<Type:16, (byte_size(Value)):16, Value/binary>>;
encode_address_attr(Type, {A, B, C, D, E, F, G, H}, Port) ->
    Value = <<0, ?FAMILY_IPV6, Port:16, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>,
    <<Type:16, (byte_size(Value)):16, Value/binary>>.

encode_xor_address_attr(Type, {A, B, C, D}, Port, _TxnId) ->
    XPort = Port bxor (?MAGIC_COOKIE bsr 16),
    <<MC1, MC2, MC3, MC4>> = <<?MAGIC_COOKIE:32>>,
    XA = A bxor MC1, XB = B bxor MC2, XC = C bxor MC3, XD = D bxor MC4,
    Value = <<0, ?FAMILY_IPV4, XPort:16, XA, XB, XC, XD>>,
    <<Type:16, (byte_size(Value)):16, Value/binary>>;
encode_xor_address_attr(Type, {A, B, C, D, E, F, G, H}, Port, TxnId) ->
    XPort = Port bxor (?MAGIC_COOKIE bsr 16),
    <<MC:32>> = <<?MAGIC_COOKIE:32>>,
    XorKey = <<MC:32, TxnId/binary>>,
    <<X1:16, X2:16, X3:16, X4:16, X5:16, X6:16, X7:16, X8:16>> = XorKey,
    Value = <<0, ?FAMILY_IPV6, XPort:16,
              (A bxor X1):16, (B bxor X2):16, (C bxor X3):16, (D bxor X4):16,
              (E bxor X5):16, (F bxor X6):16, (G bxor X7):16, (H bxor X8):16>>,
    <<Type:16, (byte_size(Value)):16, Value/binary>>.

encode_string_attr(Type, Str) when is_list(Str) ->
    encode_string_attr(Type, list_to_binary(Str));
encode_string_attr(Type, Str) when is_binary(Str) ->
    Padded = pad4(Str),
    <<Type:16, (byte_size(Str)):16, Padded/binary>>.

encode_error_code(Code, Reason) when is_list(Reason) ->
    encode_error_code(Code, list_to_binary(Reason));
encode_error_code(Code, Reason) when is_binary(Reason) ->
    Class = Code div 100,
    Number = Code rem 100,
    Value = <<0:16, Class:8, Number:8, Reason/binary>>,
    Padded = pad4(Value),
    <<?ATTR_ERROR_CODE:16, (byte_size(Value)):16, Padded/binary>>.

%%--------------------------------------------------------------------
%% Internal: Decode attributes
%%--------------------------------------------------------------------
decode_attributes(Data, TxnId) ->
    decode_attributes(Data, TxnId, []).

decode_attributes(<<>>, _TxnId, Acc) ->
    lists:reverse(Acc);
decode_attributes(<<Type:16, Length:16, Rest/binary>>, TxnId, Acc) ->
    PadLen = (4 - (Length rem 4)) rem 4,
    TotalLen = Length + PadLen,
    case Rest of
        <<Value:Length/binary, _Pad:PadLen/binary, More/binary>> ->
            Attr = decode_attribute(Type, Value, TxnId),
            decode_attributes(More, TxnId, [Attr | Acc]);
        <<Value:Length/binary>> when PadLen > 0, byte_size(Rest) =:= Length ->
            %% Last attribute may not be padded
            Attr = decode_attribute(Type, Value, TxnId),
            lists:reverse([Attr | Acc]);
        _ when byte_size(Rest) < TotalLen ->
            %% Incomplete, return what we have
            lists:reverse(Acc)
    end.

decode_attribute(?ATTR_MAPPED_ADDRESS, Value, _TxnId) ->
    {mapped_address, decode_address(Value)};
decode_attribute(?ATTR_XOR_MAPPED_ADDRESS, Value, TxnId) ->
    {xor_mapped_address, decode_xor_address(Value, TxnId)};
decode_attribute(?ATTR_SOFTWARE, Value, _TxnId) ->
    {software, binary_to_list(Value)};
decode_attribute(?ATTR_ERROR_CODE, <<_:16, Class:8, Number:8, Reason/binary>>, _TxnId) ->
    {error_code, {Class * 100 + Number, binary_to_list(Reason)}};
decode_attribute(?ATTR_USERNAME, Value, _TxnId) ->
    {username, Value};
decode_attribute(?ATTR_REALM, Value, _TxnId) ->
    {realm, binary_to_list(Value)};
decode_attribute(?ATTR_NONCE, Value, _TxnId) ->
    {nonce, Value};
decode_attribute(?ATTR_MESSAGE_INTEGRITY, Value, _TxnId) ->
    {message_integrity, Value};
decode_attribute(?ATTR_FINGERPRINT, <<FP:32>>, _TxnId) ->
    {fingerprint, FP};
decode_attribute(?ATTR_UNKNOWN_ATTRIBUTES, Value, _TxnId) ->
    {unknown_attributes, [T || <<T:16>> <= Value]};
decode_attribute(Type, Value, _TxnId) ->
    {Type, Value}.

decode_address(<<0, ?FAMILY_IPV4, Port:16, A, B, C, D>>) ->
    {{A, B, C, D}, Port};
decode_address(<<0, ?FAMILY_IPV6, Port:16, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {{A, B, C, D, E, F, G, H}, Port}.

decode_xor_address(<<0, ?FAMILY_IPV4, XPort:16, XA, XB, XC, XD>>, _TxnId) ->
    Port = XPort bxor (?MAGIC_COOKIE bsr 16),
    <<MC1, MC2, MC3, MC4>> = <<?MAGIC_COOKIE:32>>,
    {{XA bxor MC1, XB bxor MC2, XC bxor MC3, XD bxor MC4}, Port};
decode_xor_address(<<0, ?FAMILY_IPV6, XPort:16, Rest/binary>>, TxnId) ->
    Port = XPort bxor (?MAGIC_COOKIE bsr 16),
    <<MC:32>> = <<?MAGIC_COOKIE:32>>,
    XorKey = <<MC:32, TxnId/binary>>,
    <<X1:16, X2:16, X3:16, X4:16, X5:16, X6:16, X7:16, X8:16>> = XorKey,
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> = Rest,
    {{A bxor X1, B bxor X2, C bxor X3, D bxor X4,
      E bxor X5, F bxor X6, G bxor X7, H bxor X8}, Port}.

%%--------------------------------------------------------------------
%% Internal: Pad binary to 4-byte boundary
%%--------------------------------------------------------------------
pad4(Bin) ->
    case byte_size(Bin) rem 4 of
        0 -> Bin;
        N -> <<Bin/binary, 0:((4-N)*8)>>
    end.
