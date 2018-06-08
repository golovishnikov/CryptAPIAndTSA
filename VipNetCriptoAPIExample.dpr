program VipNetCriptoAPIExample;

uses
  Forms,
  MainForm in 'MainForm.pas' {frmMain},
  WcryptHelper in 'WcryptHelper.pas',
  VipNet in 'VipNet.pas',
  TSP in 'TSP.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
