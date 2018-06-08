unit TSP;

interface

uses
  Windows, Classes, SysUtils, asn1util, synacode, clHTTPSendEx, Contnrs;

type
  EASN1Exception = class(Exception);
  ETSPException = class(Exception)
  private
    FCode: Integer;
    FCodeString: string;
    FFailureCode: Integer;
    FFailureCodeString: string;
  public
    constructor Create(const Code, FailureCode: Integer; FailureCodeString: string = ''); overload;
    property Code: Integer read FCode;
    property CodeString: string read FCodeString;
    property FailureCode: Integer read FFailureCode;
    property FailureCodeString: string read FFailureCodeString;
  end;


procedure ASN1AsXML(Memory: PAnsiChar; MemorySize: Cardinal; OutStream: TStream; Pos: Integer = 0; Level: Integer = 0);
function ASN1ExtractSequence(OID: String; Memory: PAnsiChar; MemorySize: Cardinal): AnsiString;
procedure TSPGetResponse(TimeStampServer, Hash: string; Response: TStream);

implementation

uses VipNet;

type
  TASN1Tree = class
  private
    FItems: TObjectList;
    FDataSize: Integer;
    FDataType: Integer;
    FOffset: Integer;
    FNodeSize: Integer;
    FNode: PAnsiChar;
    FData: PAnsiChar;
    function GetData: AnsiString;
    function GetItems(Index: Integer): TASN1Tree;
    function GetNode: AnsiString;
    procedure ParseItems;
  public
    constructor Create(ABuf: PAnsiChar; ASize: Integer);
    destructor Destroy; override;
    property Items[Index: Integer]: TASN1Tree read GetItems;
    property Offset: Integer read FOffset;
    property Node: AnsiString read GetNode;
    property PNode: PAnsiChar read FNode;
    property NodeSize: Integer read FNodeSize;
    property DataType: Integer read FDataType;
    property Data: AnsiString read GetData;
    property PData: PAnsiChar read FData;
    property DataSize: Integer read FDataSize;

    function Count: Integer;
  end;

constructor ETSPException.Create(const Code, FailureCode: Integer; FailureCodeString: string = '');
var
  S: string;
begin
  FCode:=Code;
  FFailureCode:=FailureCode;
  case FCode of
  0: FCodeString:='';
  1: FCodeString:='Modifications';
  2: FCodeString:='Rejection';
  3: FCodeString:='Waiting';
  4: FCodeString:='Revocation warning';
  5: FCodeString:='Revocation notification';
  else FCodeString:='Code='+IntToStr(FCode);
  end;
  if FailureCodeString<>'' then
    FFailureCodeString:=FailureCodeString
  else
  case FFailureCode of
  0: FFailureCodeString:='Bad failure';
  1: FFailureCodeString:='The request data is incorrect (for notary services)';
  2: FFailureCodeString:='The authority indicated in the request is different from the one creating the response token';
  4: FFailureCodeString:='The data submitted has the wrong format';
  8: FFailureCodeString:='No certificate could be found matching the provided criteria';
  16: FFailureCodeString:='MessageTime was not sufficiently close to the system time, as defined by local policy';
  32: FFailureCodeString:='Transaction not permitted or supported';
  64: FFailureCodeString:='Integrity check failed';
  128: FFailureCodeString:='Unrecognized or unsupported algorithm identifier';
  else FFailureCodeString:='FailureCode='+IntToStr(FFailureCode);
  end;
  S:=FCodeString;
  if S<>'' then S:=S+': ';
  inherited Create(S+FFailureCodeString);
end;

const
  ASN1_ROOT = -1;
  ASN1_BOOL = $01;
  ASN1_BIT_STRING = $03;
  ASN1_UTF8_STRING = $0c;
  ASN1_NUMERIC_STRING	= $12;
  ASN1_PRINTABLE_STRING = $13;
  ASN1_IA5_STRING	= $16;
  ASN1_UTC_TIME	= $17;
  ASN1_BMP_STRING = $1e;
  ASN1_SEQUENCE = $30;
  ASN1_CONTEXT_SPECIFIC	= $a0;

function ASNEncOIDItem(Value: Integer): string;
begin
  Result:='';
  repeat
    Result:=AnsiChar((Value mod 128) or $80*Ord(Length(Result)>0))+Result;
    Value:=Value div 128;
  until Value=0;
end;

function MibToId(Mib: string): string;
var
  I: Integer;
  SL: TStringList;
begin
  Result:='';
  SL := TStringList.Create;
  try
    SL.Delimiter := '.';
    SL.DelimitedText := Mib;
    for I := 0 to SL.Count - 1 do
    begin
      case I of
        0:  Result := SL[I];
        1:  Result:=ASNEncOIDItem(StrToInt(Result) * 40 + StrToInt(SL[I]));
        else Result := Result + ASNEncOIDItem(StrToInt(SL[I]));
      end;
    end;
  finally
    SL.Free;
  end;
end;

function ASN1DecOIDItem(var Buffer: PAnsiChar): Integer;
begin
  Result:=0;
  repeat
    Result:=Result*128 + Ord(Buffer^) and $7F;
    Inc(Buffer);
  until Ord((Buffer-1)^)<$80;
end;

function IdToMib(Id: PAnsiChar; Size: Integer): string;
var
  X: Integer;
  B: PAnsiChar;
begin
  B := Id + Size;
  X := ASN1DecOIDItem(Id);
  Result := IntToStr(X div 40) + '.' + IntToStr(X mod 40);
  while Id < B do Result := Result + '.' + IntToStr(ASN1DecOIDItem(Id));
end;

function ASN1DecInt(Data: PAnsiChar; Size: Integer): Integer;
var
  n: Integer;
  neg: Boolean;
  x: Byte;
begin
  Result := 0;
  neg := False;
  for n := 1 to Size do
  begin
    x := Ord(Data^);
    if (n = 1) and (x > $7F) then
      neg := True;
    if neg then
      x := not x;
    Result := Result * 256 + x;
    Inc(Data);
  end;
  if neg then
    Result := -(Result + 1);
end;

function ASN1DecodeItem(Memory: PAnsiChar; out DataType: Integer; out Data: PAnsiChar; out Size: Integer; CheckDataType: Integer = 0): Integer;
var
  I: Integer;
begin
  Result := 0;
  Size := 0;
  DataType := Ord(Memory^);
  Inc(Memory);
  Inc(Result);
  if Ord(Memory^) < $80 then
    Size:=Ord(Memory^)
  else
    for I:=1 to Ord(Memory^) and $7F do
    begin
      Inc(Memory);
      Inc(Result);
      Size := Size * 256 + Ord(Memory^);
    end;
  Data := Memory + 1;
  Inc(Result);
  if not (CheckDataType in [0, DataType]) then
    raise EASN1Exception.Create('Datatype failed (Expected: ' + IntToStr(CheckDataType) + ', Found: ' + IntToStr(DataType) + ')');
end;

function IsASN1Include(MemoryDataType: Integer; MemoryData: PAnsiChar; MemorySize: Integer): Boolean;
var
  DataType,Size: Integer;
  Data: PAnsiChar;
begin
  Result := False;
  if (MemorySize < 5) or (MemoryDataType <> ASN1_OCTSTR) then Exit;
  ASN1DecodeItem(MemoryData,DataType,Data,Size);
  Result := (DataType in [ASN1_SEQUENCE, ASN1_UTF8_STRING]) and (Data + Size = MemoryData + MemorySize);
end;

function UTF8ToWideStr(const Buf; Size: Integer): WideString;
var
  Sz: integer;
begin
  if Size <= 0 then
  begin
    Result := '';
    Exit;
  end;

  SetLength(Result, Size);
  Sz := MultiByteToWideChar(CP_UTF8, 0, @Buf, Size, @Result[1], Size);
  SetLength(Result, Sz);
end;

function ASN1GetValueAsString(DataType: Integer; Data: PAnsiChar; DataSize: Integer): String;
var
  P: Char;
  PC, PB: PAnsiChar;
  UTF: PAnsiChar;
  I: Integer;
  SS: TMemoryStream;
begin
  case DataType of
  ASN1_INT,ASN1_BOOL:
    Result := IntToStr(ASN1DecInt(Data, DataSize));
  ASN1_NUMERIC_STRING,ASN1_IA5_STRING,ASN1_PRINTABLE_STRING,ASN1_UTC_TIME:
    SetString(Result, Data, DataSize);
  ASN1_OBJID:
    Result := IdToMib(Data, DataSize);
  ASN1_BMP_STRING:
  begin
    try
      GetMem(PB, DataSize);
      try
        Move(Data^, PB^, DataSize);
        PC := PB;
        I := 0;
        while I < DataSize do
        begin
          P := PC^;
          PC^ := (PC+1)^;
          (PC+1)^ := P;
          Inc(I, 2);
          Inc(PC, 2);
        end;
        Result := WideCharToString(PWideChar(PB));
      finally
        FreeMem(PB, DataSize);
      end;
    finally
    end;
  end;
  ASN1_UTF8_STRING:
  begin
    Result := UTF8ToWideStr(Data^, DataSize);
  end;
  else
    SetString(Result, Data, DataSize);
    Result := StringReplace(EncodeBase64(Result),#13#10,'',[rfReplaceAll]);
  end;
end;

procedure WriteToStream(S: TStream; DataType: Integer; Level: Integer; Pos: Integer; Data: PAnsiChar; Size: Integer);
var
  I: Integer;
  C: Char;
  Str: String;
begin
  C := #32;
  for I := 1 to Level do
  begin
    S.WriteBuffer(C, 1);
  end;
  Str := Format('L%d P%4.4X T%4.4X: ', [Level, Pos, DataType]);
  S.WriteBuffer(Str[1], Length(Str));
  S.WriteBuffer(Data^, Size);
  S.WriteBuffer(sLineBreak, Length(sLineBreak));
end;

procedure ASN1AsXML(Memory: PAnsiChar; MemorySize: Cardinal; OutStream: TStream; Pos: Integer = 0; Level: Integer = 0);
  procedure SaveNodeToStream(Node: TASN1Tree; Level: Integer);
  var
    I: Integer;
    S: AnsiString;
  begin
    if Node.Count > 0 then
    begin
      WriteToStream(OutStream, Node.DataType, Level, Node.Offset, Node.PData, 0);
      for I := 0 to Node.Count - 1 do
      begin
        SaveNodeToStream(Node.Items[I], Level + 1);
      end;
    end
    else
    begin
      S := ASN1GetValueAsString(Node.DataType, Node.PData, Node.DataSize);
      WriteToStream(OutStream, Node.DataType, Level, Node.Offset, @S[1], Length(S));
    end;
  end;
var
  Root: TASN1Tree;
  I: Integer;
begin
  Root := TASN1Tree.Create(Memory, MemorySize);
  Root.ParseItems;
  for I := 0 to Root.Count - 1 do
  begin
    SaveNodeToStream(Root.Items[I], Level);
  end;
end;


function ASN1ExtractSequence(OID: String; Memory: PAnsiChar; MemorySize: Cardinal): AnsiString;
  function FindSequence(Node: TASN1Tree): TASN1Tree;
  var
    Item: TASN1Tree;
    I: Integer;
  begin
    Result := nil;
    for I := 0 to Node.Count - 1 do
    begin
      Item := FindSequence(Node.Items[I]);
      if Assigned(Item) then
      begin
        Result := Item;
        Break;
      end
      else if (Node.DataType = ASN1_SEQUENCE)
        and (Node.Items[I].DataType = ASN1_OBJID)
        and (IdToMib(Node.Items[I].PNode, Node.Items[I].DataSize) = OID)
      then
      begin
        Result := Node;
        Break;
      end;
    end;
  end;
var
  Root: TASN1Tree;
  I: Integer;
  Node: TASN1Tree;
begin
  Root := TASN1Tree.Create(Memory, MemorySize);
  Root.ParseItems;
  for I := 0 to Root.Count - 1 do
  begin
    Node := FindSequence(Root.Items[I]);
    if Assigned(Node) then
    begin
      Result := Node.Node;
      Break;
    end;
  end;
end;



procedure TSPGetResponse(TimeStampServer, Hash: string; Response: TStream);
var
  S: AnsiString;
  HTTPResponse: String;
  DataType,Size: Integer;
  Memory: PAnsiChar;
  E,B: Integer;
  F: string;
  RR: Boolean;
  Request: TMemoryStream;
  HTTPClient: THTTPSendEx;
begin

  S := ASNObject(
    ASNObject(ASNEncInt(1), ASN1_INT)+
    ASNObject(
      ASNObject(
        ASNObject(MibToId('1.2.643.2.2.9'), ASN1_OBJID)+ASNObject('', ASN1_NULL),
//        ASNObject(MibToId(szOID_DOMEN_ELIP_SIGN_ALG), ASN1_OBJID)+ASNObject('', ASN1_NULL),
      ASN1_SEQ) +
      ASNObject(Hash, ASN1_OCTSTR), ASN1_SEQ) +
      ASNObject(IntToStr(GetTickCount), ASN1_INT) +
      ASNObject(Char(True),ASN1_BOOL),
  ASN1_SEQ);
  Request := TMemoryStream.Create;
  HTTPClient := THTTPSendEx.Create;
  try
    try
      HTTPClient.MimeType := 'application/timestamp-query';
      RR := HTTPClient.Post(TimeStampServer, S, Response);
      if not RR or (HTTPClient.ResponseCode < 200) or (HTTPClient.ResponseCode > 299) then
      begin
        raise ETSPException.Create(IntToStr(HTTPClient.ResponseCode)+': '+UTF8Decode(HTTPClient.ResponseString)+'. URL:'+TimeStampServer);
      end;

    except
      on E:Exception do
        raise ETSPException.Create(E.ClassName+': '+E.Message+'. URL:'+TimeStampServer);
    end;

    if not SameText(HTTPClient.MimeType,'application/timestamp-reply') then
      raise ETSPException.Create('Bad reply. Content-Type: '+HTTPClient.MimeType+'. URL:'+TimeStampServer);

    Response.Position:=0;
    Request.Clear;
    Request.CopyFrom(Response,Response.Size);
    Memory:=Request.Memory;
    ASN1DecodeItem(Memory,DataType,Memory,Size,ASN1_SEQUENCE);
    ASN1DecodeItem(Memory,DataType,Memory,Size,ASN1_SEQUENCE);
    ASN1DecodeItem(Memory,DataType,Memory,Size,ASN1_INT);
    E:=ASN1DecInt(Memory,Size);
    if E<>0 then //обработка ошибки
    begin
      B:=0;
      F:='';
      //далее может быть сразу: или код ошибки, или текст ошибки, а только потом - код ошибки
      //сервер может возвращать только код
      while True do
      begin
        Inc(Memory,Size); //переход на следующий узел
        ASN1DecodeItem(Memory,DataType,Memory,Size);
        case DataType of
        ASN1_BIT_STRING: //это код ошибки
          if Size=2 then
            B:=PByte(Memory+1)^; //второй байт
        ASN1_SEQUENCE: //это блок с текстом ошибки
        begin
          ASN1DecodeItem(Memory,DataType,Memory,Size); //получим текстовую строку об ошибке
          if DataType in [ASN1_UTF8_STRING,ASN1_PRINTABLE_STRING,ASN1_IA5_STRING,ASN1_BMP_STRING] then
          begin
            F:=ASN1GetValueAsString(DataType,Memory,Size);
            Continue;
          end;
        end;
        end;
        Break;
      end;
      raise ETSPException.Create(E,B,F);
    end;

  finally
    Request.Free;
    HTTPClient.Free;
  end;

end;

{ TASN1Tree }

function TASN1Tree.Count: Integer;
begin
  Result := FItems.Count;
end;

constructor TASN1Tree.Create(ABuf: PAnsiChar; ASize: Integer);
begin
  inherited Create;
  FItems := TObjectList.Create(True);
  FDataSize := 0;
  FDataType := ASN1_ROOT;
  FOffset := 0;
  FNodeSize := ASize;
  FNode := ABuf;
  FData := nil;
end;

destructor TASN1Tree.Destroy;
begin
  FItems.Free;
  inherited;
end;

function TASN1Tree.GetData: AnsiString;
begin
  SetLength(Result, FDataSize);
  Move(FData^, Result[1], FDataSize);
end;

function TASN1Tree.GetItems(Index: Integer): TASN1Tree;
begin
  Result := FItems[Index] as TASN1Tree;
end;

function TASN1Tree.GetNode: AnsiString;
begin
  SetLength(Result, FNodeSize);
  Move(FNode^, Result[1], FNodeSize);
end;

procedure TASN1Tree.ParseItems;
var
  LDataType, LSize: Integer;
  LData, LMemory, LMemoryEnd: PAnsiChar;
  Pos: Integer;
  Item: TASN1Tree;
begin
  FItems.Clear;

  LMemory := FNode;
  LMemoryEnd := LMemory + FNodeSize;
  Pos := FOffset;
  while LMemory < LMemoryEnd do
  begin
    Pos := Pos + ASN1DecodeItem(LMemory, LDataType, LData, LSize);
    Item := TASN1Tree.Create(LData, LSize);
    Item.FDataSize := LSize;
    Item.FDataType := LDataType;
    Item.FOffset := Pos;
    Item.FData := LData;
    FItems.Add(Item);
    if ((LDataType and $20)<>0) or IsASN1Include(LDataType, LData, LSize) then
    begin
      Item.ParseItems;
    end;
    LMemory := LData + LSize;
    Pos := Pos + LSize;
  end;
end;

initialization

finalization

end.
