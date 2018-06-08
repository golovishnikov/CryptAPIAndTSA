unit LogInterface;

interface

uses Windows, Classes, Forms, Log4D;

procedure Log4DReconfig(Force: Boolean = False); overload;
procedure Log4DReconfig(Props: TStringList); overload;
    { Имя конфигурационного файла }
function Log4DConfigFileName: String;

implementation

uses SysUtils;

const
  CRLF = #13#10;
  defConfig =
    'log4d.appender.logfile=TLogRollingFileAppender' + CRLF +
    'log4d.appender.logfile.maxFileSize=10000KB' + CRLF +
    'log4d.appender.logfile.maxBackupIndex=3' + CRLF +
    'log4d.appender.logfile.append=true' + CRLF +
    'log4d.appender.logfile.lockingModel=InterProcessLock' + CRLF +
    'log4d.appender.logfile.fileName=app_log4d.log' + CRLF +
    'log4d.appender.logfile.layout=TLogPatternLayout' + CRLF +
    'log4d.appender.logfile.layout.dateFormat=yyyy-mm-dd hh:nn:ss.zzz' + CRLF +
    'log4d.appender.logfile.layout.pattern=%d %p [%c] (%h:%w:%a:%t) - %m%n' + CRLF + CRLF +
    'log4d.rootLogger=debug,logfile';

var
  CriticalSection: TRTLCriticalSection;
  LogInitialized: boolean;

procedure Log4DReconfig(Force: Boolean = False);
begin
  if not Force and LogInitialized then Exit;
//  EnterCriticalSection(CriticalSection);
  try
    LogInitialized := False;
    TLogPropertyConfigurator.ResetConfiguration;
    TLogPropertyConfigurator.Configure(Log4DConfigFileName);
    LogInitialized := True;
  finally
//    LeaveCriticalSection(CriticalSection);
  end;
end;

procedure Log4DReconfig(Props: TStringList);
begin
  try
    LogInitialized := False;
    TLogPropertyConfigurator.ResetConfiguration;
    TLogPropertyConfigurator.Configure(Props);
    LogInitialized := True;
  finally
  end;
end;

function Log4DConfigFileName: String;
var
  FS: TFileStream;
  S: String;
begin
  Result := ExtractFilePath(GetModuleName(0)) + 'log4d.cfg';
  if not FileExists(Result) then
  begin
    FS := TFileStream.Create(Result, fmCreate);
    try
      S := defConfig;
      FS.WriteBuffer(Pointer(S)^, length(S));
    finally
      FS.Free;
    end;
  end;
end;

initialization
  { Synchronisation. }
  InitializeCriticalSection(CriticalSection);
  LogInitialized := False;
finalization
  { Synchronisation. }
  DeleteCriticalSection(CriticalSection);

end.
