unit MainForm;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, VipNet, JwaWinCrypt, WCryptHelper;

type
  TfrmMain = class(TForm)
    cbDeattached: TCheckBox;
    cbTSA: TCheckBox;
    edTSAUrl: TEdit;
    btSign: TButton;
    mLog: TMemo;
    OpenDialog: TOpenDialog;
    Label1: TLabel;
    edCert: TEdit;
    btSelectCert: TButton;
    procedure btSignClick(Sender: TObject);
    procedure btSelectCertClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.btSignClick(Sender: TObject);
var
  Cert: PCCERT_CONTEXT;
  certName: array[0..255] of char;
  TSPUrl: String;
begin
  if not OpenDialog.Execute then Exit;

  mLog.Clear;
  Cert := nil;
  if edCert.Text <> '' then
    Cert := FindSignerCert(MY_CERT_STORE_NAME, edCert.Text);
  if not Assigned(Cert) then
    Cert := GetSignerCert(Self.Handle, MY_CERT_STORE_NAME);
  if not Assigned(Cert) then Exit;

  try
    if edCert.Text = '' then
    begin
      if (CertGetNameString(Cert, CERT_NAME_ATTR_TYPE, 0, nil, @certName, 128) <> 0) then
      begin
          edCert.Text := certName;
      end;
    end;
    if cbTSA.Checked then
      TSPUrl := edTSAUrl.Text
    else
      TSPUrl := '';
    SignFileSimple(Cert, OpenDialog.FileName, cbDeattached.Checked, TSPUrl);
    mLog.Lines.Add('Signed ' + OpenDialog.FileName);
  finally
    CertFreeCertificateContext(Cert);
  end;

end;

procedure TfrmMain.btSelectCertClick(Sender: TObject);
var
  Cert: PCCERT_CONTEXT;
  certName: array[0..255] of char;
begin
  Cert := GetSignerCert(Self.Handle, MY_CERT_STORE_NAME);
  if not Assigned(Cert) then Exit;

  try
    if (CertGetNameString(Cert, CERT_NAME_ATTR_TYPE, 0, nil, @certName, 128) <> 0) then
    begin
      edCert.Text := certName;
    end;
  finally
    CertFreeCertificateContext(Cert);
  end;
end;

end.
