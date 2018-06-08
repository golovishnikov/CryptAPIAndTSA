unit RemoteLogSender;

interface

uses Windows, Messages, SysUtils,  Classes, InterfacedForm, Forms, AbZipper,
  AbUtils, commonMIS;


// Отправка массива значений на сервер.
// Data - это список пар key-value.
/// При записи значения используется стандартный разделитель
function send(AURL: string; Data: TStrings): string;

// Отправка данных пингового запроса к DBMIS
// Функция дополняет отправляемые данные сведениями о пользователе
// и отправляет данные в отдельном потоке.
procedure sendPingLog(Data: TStrings);

// Отправка текстового представления json объекта.
// Функци предназначена для отправки логов из Log4D
// при помощи TLogHttpAppender
// Функция создает отдельный процесс для отправки данных.
procedure sendJsonText(json: string);
// Установить разрешение на отправку логов на севрер
procedure EnableJsonSend(Enabled: boolean);

// Отправка спика значений на сервере с дополнительным заголовком
function sendH(AURL: string; Data: TStrings; Headers: TStrings): string;

implementation

uses
  httpsend, ssl_openssl, blcksock, synautil, synaip, synacode, synsock,
  OSUserInfo, pingsend, Math, IniFiles, variants, superobject;

type
  TSendLogThread = class(TThread)
  private
    FData: TStringList;
    Fjson: string;
    FURL: string;
  public
    constructor Create(URL: string; Data: TStrings; jsonText: string); overload;
    destructor Destroy; override;
    procedure Execute; override;
  end;


var
  FMainForm: IInterfacedForm;
  FDbServer: string;
  FDbName: string;
  FJsonSendEnabled: boolean;

function GetLogUrl: string;
begin
  Result := 'https://ws.ctmed.ru/remotelog/index.php'
end;

function HTTPEncodeStrings(SL: TStrings): UTF8String;
var
  I: Integer;
begin
  Result := '';
  for I:=0 to SL.Count-1 do
  begin
    if I>0 then
      Result := Result + '&';
    Result := Result + UTF8Encode(SL.Names[I])+'='+UTF8Encode(SL.ValueFromIndex[I]);
  end;
end;

function send(AURL: string; Data: TStrings): string;
begin
  Result := sendH(AURL, Data, nil);
end;

procedure SetMainForm;
begin
  if FMainForm=nil then
    if Application.MainForm.InheritsFrom(TInterfacedForm) then
      TInterfacedForm(Application.MainForm).QueryInterface(IInterfacedForm,
        FMainForm)
end;

procedure addUserInfo(Data: TStringList);
var
  user: TCTMUserInfo;
begin
  SetMainForm;
  if not Assigned(FMainForm)then Exit;

  user := FMainForm.GetLastUser;

  Data.Add('lan.ip.address='+GetLocalIP);
  Data.Add('client.id='+IntToStr(user.id));
  Data.Add('client.name='+user.user);
  Data.Add('client.post='+user.dol);
  Data.Add('client.group.id='+IntToStr(user.type_id));
  Data.Add('client.group.name='+user.group_name);
  Data.Add('clinic.id='+IntToStr(user.lpu_id));
end;

procedure addDbName(Data: TStrings);
var
  ini: TIniFile;
begin
  if (FDbName = '') or (FDbServer = '') then
  begin
    ini:= TIniFile.Create(ChangeFileExt(Application.ExeName, '.ini'));
    try
      FDbServer := ini.ReadString('FIBDataBase', 'ServerName', 'fb.ctmed.ru');
      FDbName := ini.ReadString('FIBDataBase', 'DatabaseName', 'dbmis');
    finally
      ini.Free;
    end;
  end;
  Data.Values['db.server'] := FDbServer;
  Data.Values['db.name'] := FDbName;
end;

procedure parseJson(Data: TStrings; jsonText: string);
  procedure parse(p: string; o: ISuperObject);
  var
    iter: TSuperObjectIter;
  begin
    if not Assigned(o) then Exit;
    if o.IsType(stObject) then
    begin
      if ObjectFindFirst(o, iter) then
      repeat
        parse(iter.key, iter.val);
      until not ObjectFindNext(iter);
    end
    else
      Data.Add(p + '=' + VarToStr(o.AsString));
  end;
var
  json: ISuperObject;
begin
  json := SO(jsonText);
  parse('message', json);
end;

procedure EnableJsonSend(Enabled: boolean);
begin
  FJsonSendEnabled := Enabled;
end;

procedure sendJsonText(json: string);
var
  tmp: TStringList;
begin
  if not FJsonSendEnabled then Exit;
  tmp := TStringList.Create;
  try
    addUserInfo(tmp);
    addDbName(tmp);
    TSendLogThread.Create(GetLogUrl, tmp, json);
  finally
    tmp.Free;
  end;
end;


function sendH(AURL: string; Data: TStrings; Headers: TStrings): string;
var
  Resp: TStringStream;
  HTTP: THTTPSend;
  I: Integer;
  tmp: TStringList;
begin
  HTTP := THTTPSend.Create;
  Resp := TStringStream.Create('');
  tmp := TStringList.Create;
  try
    addUserInfo(tmp);
    tmp.AddStrings(Data);
    WriteStrToStream(HTTP.Document, HTTPEncodeStrings(tmp));
    HTTP.MimeType := 'application/x-www-form-urlencoded';
    HTTP.Headers.Add('MISAUTH: CDAF5A2C-4250-4D0E-B427-8237736E3ED8');
    if Assigned(Headers) then
      for I:=0 to Headers.Count-1 do
        HTTP.Headers.Add(Headers.Names[I] + ': ' + Headers.ValueFromIndex[I]);
    if HTTP.HTTPMethod('POST', AURL) then
      Resp.CopyFrom(HTTP.Document, 0);
    Result := Resp.DataString;
  finally
    tmp.Free;
    Resp.Free;
    HTTP.Free;
  end;
end;

procedure sendPingLog(Data: TStrings);
var
  tmp: TStringList;
begin
  tmp := TStringList.Create;
  try
    addUserInfo(tmp);
    tmp.AddStrings(Data);
    TSendLogThread.Create(GetLogUrl, tmp, '');
  finally
    tmp.Free;
  end;
end;
{ TSendLogThread }

constructor TSendLogThread.Create(URL: string; Data: TStrings; jsonText: string);
begin
  FData := TStringList.Create;
  FData.AddStrings(Data);
  FreeOnTerminate := True;
  Fjson := jsonText;
  FURL := URL;
  inherited Create(False);
end;

destructor TSendLogThread.Destroy;
begin
  FData.Free;
  inherited;
end;


procedure parseSQLmessage(Data: TStrings);

const
  sExecute = ': [Execute]';
  sPrepare = ': [Prepare]';
  sTickCount = 'Execute tick count';
  sAffected = 'Rows Affected:';

  function isParam(S: string): boolean;
  var
    I, J: Integer;
  begin
    Result := False;
    if (Length(S)>3) and (S[1]=' ') and (S[2]=' ') and (S[3]<>' ') then
    begin
      I := 3;
      J := Length(S);
      while (I<=J) and (S[I]<>' ') do
      begin
        if not (S[I] in ['A'..'Z', '0'..'9', '_']) then
        begin
          Exit;
        end;
        Inc(I);
      end;
      if I+1 < J then
      begin
        Result := (S[I+1]='=') and (S[I+2]=' ');
      end;
    end;
  end;
  procedure parseExecute(msg: string);
  var
    SL: TStringList;
    I, J: Integer;
    S: string;
  begin
    Data.Add('log.sql.type=execute');
    SL := TStringList.Create;
    try
      SL.Text := msg;
      I := SL.Count - 1;
      J := pos(sTickCount, SL[I]);
      if (J>0) then
      begin
        J := J+Length(sTickCount);
        Data.Add('exec.time.server='+copy(SL[I], J, Length(SL[I])-J+1));
        Dec(I);
      end;
      J := pos(sAffected, SL[I]);
      if (J>0) then
      begin
        J := J+Length(sAffected);
        Data.Add('rows.affected='+copy(SL[I], J, Length(SL[I])-J+1));
        Dec(I);
      end;
      S := '';
      while isParam(SL[I]) do
      begin
        S := SL[I] + sLineBreak + S;
        Dec(I);
      end;
      if S<>'' then
        Data.Add('params='+S);
      J := I;
      S := '';
      for I:=0 to J do
      begin
        S := S + SL[I] + sLineBreak;
      end;
      if S<>'' then
        Data.Values['message'] := S;
    finally
      SL.Free;
    end;
  end;

var
  msg: string;
  I: Integer;
begin
  msg := Data.Values['message'];
  I := pos(sExecute, msg);
  if I > 0 then
  begin
    I := I+Length(sExecute);
    parseExecute(trim(copy(msg, I, Length(msg)-I+1)));
    Exit;
  end
end;

procedure WriteGzipToStream(Stream: TStream; Data: UTF8String);
var
  Zip: TAbZipper;
  MS: TMemoryStream;
begin
  Zip := TAbZipper.Create(nil);
  MS := TMemoryStream.Create;
  try
    Zip.ArchiveType := atGzip;
    Zip.ForceType := True;
    Zip.Stream := Stream;
    WriteStrToStream(MS, Data);
    MS.Position := 0;
    Zip.AddFromStream('', MS);
  finally
    MS.Free;
    Zip.Free;
  end;
end;

procedure TSendLogThread.Execute;
var
  Resp: TStringStream;
  HTTP: THTTPSend;
  tmp: TStringList;
  S: string;
  FContent: UTF8String;
  URL: string;
begin
  HTTP := THTTPSend.Create;
  Resp := TStringStream.Create('');
  tmp := TStringList.Create;
  try
    tmp.Delimiter := '&';
    tmp.AddStrings(FData);
    if Fjson<>'' then
    begin
      parseJson(tmp, Fjson);
      parseSQLmessage(tmp);
    end;
    URL := AppParamValue('/logurl');
    // Если удалось получить имя сервера
    if URL='' then
      URL := FURL;
    if URL<>'' then
    begin
      FContent := HTTPEncodeStrings(tmp);
      if Length(FContent)<256 then
        WriteStrToStream(HTTP.Document, FContent)
      else
      begin
        WriteGzipToStream(HTTP.Document, FContent);
        HTTP.Headers.Add('Content-Encoding: gzip');
      end;
      HTTP.MimeType := 'application/x-www-form-urlencoded';
      HTTP.Headers.Add('MISAUTH: CDAF5A2C-4250-4D0E-B427-8237736E3ED8');
      HTTP.Headers.Add('PINGLOG: 1');
      if HTTP.HTTPMethod('POST', URL) then
        Resp.CopyFrom(HTTP.Document, 0);
      S := Resp.DataString;
      S := '';
    end;
  finally
    tmp.Free;
    Resp.Free;
    HTTP.Free;
  end;
end;

end.
