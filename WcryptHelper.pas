unit WcryptHelper;

interface

uses
  Windows, Classes, SysUtils, JwaWinCrypt, JwaCryptUIApi, VipNet, TSP, asn1util;

const
  CERT_STORE_NAME = 'MY';
  MY_CERT_STORE_NAME = CERT_STORE_NAME;
  CA_CERT_STORE_NAME = 'CA';
  ROOT_CERT_STORE_NAME = 'ROOT';
  MY_ENCODING_TYPE = PKCS_7_ASN_ENCODING or X509_ASN_ENCODING;

type
  ECryptException = class(Exception);

function CryptCheck(RetVal: BOOL; FuncName: string): BOOL;
function GetSignerCert(hwnd: HWND; StoreName: String): PCCERT_CONTEXT;
function FindSignerCert(StoreName: String; Name: String): PCCERT_CONTEXT;

procedure SignFileSimple(SignerCert: PCCERT_CONTEXT; FileName: string;
  DetachedSign: boolean; TSPUrl: String);
procedure SignFile(SignerCert: PCCERT_CONTEXT; FileName: string;
  StreamOut: TMemoryStream; DetachedSign: boolean; TSPUrl: AnsiString);
procedure SignStream(SignerCert: PCCERT_CONTEXT; StreamIn: TMemoryStream;
  StreamOut: TMemoryStream; DetachedSign: boolean; TSPUrl: AnsiString);

implementation

function CryptCheck(RetVal: BOOL; FuncName: string): BOOL;
begin
  try
    Result := Win32Check(RetVal);
  except
    on E: EOSError do raise ECryptException.Create(FuncName + sLineBreak + E.Message);
    else raise;
  end;
end;

function GetSignerCert(hwnd: HWND; StoreName: String): PCCERT_CONTEXT;
var
  hCertStoreHandle: HCERTSTORE;
begin
  hCertStoreHandle := CertOpenSystemStore(0, @StoreName[1]);
  if (not assigned(hCertStoreHandle)) then
    CryptCheck(False, Format('CertOpenSystemStore: %s', [StoreName]));
  try
    Result := CryptUIDlgSelectCertificateFromStore(
      hCertStoreHandle,
      hwnd,
      nil,
      nil,
      CRYPTUI_SELECT_LOCATION_COLUMN,
      0,
      nil);
  finally
    try
      CertCloseStore(hCertStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
    except
    end;
  end;
end;

function FindSignerCert(StoreName: String; Name: String): PCCERT_CONTEXT;
var
  hCertStoreHandle: HCERTSTORE;
  cName: PWideChar;
begin
  hCertStoreHandle := CertOpenSystemStore(0, @StoreName[1]);
  if (not assigned(hCertStoreHandle)) then
    CryptCheck(False, Format('CertOpenSystemStore: %s', [StoreName]));
  try
    GetMem(cName, 2 * Length(Name) + 1);
    try
      StringToWideChar(Name, cName, 2 * Length(Name) + 1);
      Result := CertFindCertificateInStore(hCertStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_SUBJECT_STR, cName, nil );
    finally
      FreeMem(cName);
    end;
  finally
    try
      CertCloseStore(hCertStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
    except
    end;
  end;
end;

procedure GetHashStream(Cert: PCCERT_CONTEXT; DataStream: TMemoryStream; var Hash: String);
var
  hProv: HCRYPTPROV;
  DataLen: DWORD;
  hHash: HCRYPTHASH;
  dwKeySpec: DWORD;
  OutStream: TMemoryStream;
begin
  CryptCheck(CryptAcquireCertificatePrivateKey(
      Cert,
      0,
      nil,
      hProv,
      @dwKeySpec,
      nil), 'CryptAcquireCertificatePrivateKey');
  OutStream := TMemoryStream.Create;
  try

    begin
      CryptCheck(CryptCreateHash(hProv, CALG_GR3411, 0, 0, hHash), 'CryptCreateHash');
      try
        CryptCheck(CryptHashData(hHash, DataStream.Memory, DataStream.Size, 0), 'CryptHashData');
        CryptCheck(CryptGetHashParam(hHash, HP_HASHVAL, nil, DataLen, 0), 'CryptGetHashParam');
        OutStream.Size := DataLen;
        CryptCheck(CryptGetHashParam(hHash, HP_HASHVAL, OutStream.Memory, DataLen, 0), 'CryptGetHashParam');
        SetLength(Hash, DataLen);
        Move(OutStream.Memory, PAnsiChar(@Hash[1])^, DataLen);
      finally
        CryptCheck(CryptDestroyHash(hHash), 'CryptDestroyHash');
      end;
    end;
  finally
    OutStream.Free;
    CryptCheck(CryptReleaseContext(hProv, 0), 'CryptReleaseContext');
  end;
end;


procedure SignStream(SignerCert: PCCERT_CONTEXT; StreamIn: TMemoryStream;
  StreamOut: TMemoryStream; DetachedSign: boolean; TSPUrl: AnsiString);
var
  MessageArray: array of PByte;
  MessageSize: array of DWORD;
  SigParams: CRYPT_SIGN_MESSAGE_PARA;
  cbSignedMessage: DWORD;
  caSigTime, caTimeStamp: CRYPT_ATTRIBUTE;
  FTime: TFileTime;
  cabSigTime, cabTimeStamp: CRYPT_ATTR_BLOB;
  pbSigTime: array of byte;
  cbSigTime: DWORD;
  Hash: AnsiString;

  SignStream: TMemoryStream;
  TimeStampStream: TMemoryStream;
  TimeStampBytes: AnsiString;

  hMsg: HCRYPTMSG;
  cbDigestSize: DWORD;
  pbDigestSize: TMemoryStream;
  encodedAttributeSize: DWORD;
  encodedAttribute: TMemoryStream;
  unauthenticatedParam: CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA;
  encodedMessageLength: DWORD;
  pData: TMemoryStream;
  pbSignedMessage: TMemoryStream;
begin
  if not Assigned(SignerCert) then
  begin
    raise ECryptException.Create('Signer certificate is null');
    Exit;
  end;
  hMsg := nil;
  pbSignedMessage := TMemoryStream.Create;
  TimeStampStream := TMemoryStream.Create;
  SignStream := TMemoryStream.Create;
  pbDigestSize := TMemoryStream.Create;
  encodedAttribute := TMemoryStream.Create;
  pData := TMemoryStream.Create;
  try
    // Sig params
    SetLength(MessageArray, 1);
    SetLength(MessageSize, 1);

    MessageArray[0] := StreamIn.Memory;
    MessageSize[0] := StreamIn.Size;
    FillChar(SigParams, SizeOf(CRYPT_SIGN_MESSAGE_PARA), #0);
    SigParams.cbSize := SizeOF(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType := PKCS_7_ASN_ENCODING or X509_ASN_ENCODING;
    SigParams.pSigningCert := SignerCert;
    SigParams.HashAlgorithm.pszObjId := SignerCert.pCertInfo.SignatureAlgorithm.pszObjId;
    SigParams.cMsgCert := 1;
    SigParams.rgpMsgCert := @SignerCert;

    GetSystemTimeAsFileTime(fTime);
    CryptEncodeObject(MY_ENCODING_TYPE, szOID_RSA_signingTime, @fTime, nil, cbSigTime);
    SetLength(pbSigTime, cbSigTime);
    CryptEncodeObject(MY_ENCODING_TYPE, szOID_RSA_signingTime, @fTime, Pointer(pbSigTime), cbSigTime);
    cabSigTime.cbData := cbSigTime;
    cabSigTime.pbData := Pointer(pbSigTime);
    caSigTime.pszObjId := szOID_RSA_signingTime;
    caSigTime.cValue := 1;
    caSigTime.rgValue := @cabSigTime;
    SigParams.cAuthAttr := 1;
    SigParams.rgAuthAttr := @caSigTime;

    cbSignedMessage := 0;
    CryptCheck(CryptSignMessage(@SigParams, DetachedSign, 1, Pointer(MessageArray), Pointer(MessageSize), nil, cbSignedMessage), 'CryptSignMessage');
    pbSignedMessage.Size := cbSignedMessage;
    CryptCheck(CryptSignMessage(@SigParams, DetachedSign, 1, Pointer(MessageArray), Pointer(MessageSize), pbSignedMessage.Memory, cbSignedMessage), 'CryptSignMessage');
    pbSignedMessage.Size := cbSignedMessage;
    StreamOut.Clear;
    StreamOut.CopyFrom(pbSignedMessage, 0);

    if TSPUrl <> '' then
    begin
      hMsg := CryptMsgOpenToDecode(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0, nil, nil);
      if hMsg <> nil then
      begin
        pbSignedMessage.Position := 0;
        CryptCheck(CryptMsgUpdate(hMsg, pbSignedMessage.Memory, pbSignedMessage.Size, True), 'CryptMsgUpdate');
        cbDigestSize := 0;
        CryptCheck(CryptMsgGetParam(hMsg, CMSG_ENCRYPTED_DIGEST, 0, nil, cbDigestSize), 'CryptMsgGetParam');
        pbDigestSize.Size := cbDigestSize;
        CryptCheck(CryptMsgGetParam(hMsg, CMSG_ENCRYPTED_DIGEST, 0, pbDigestSize.Memory, cbDigestSize), 'CryptMsgGetParam');
        GetHashStream(SignerCert, pbDigestSize, Hash);

        TSPGetResponse(TSPUrl, Hash, TimeStampStream);

        TimeStampStream.Position := 0;
        TimeStampBytes := ASN1ExtractSequence(szOID_RSA_signedData, TimeStampStream.Memory, TimeStampStream.Size);
        TimeStampBytes := ASNObject(TimeStampBytes, ASN1_SEQ);
        TimeStampStream.Clear;
        TimeStampStream.WriteBuffer(TimeStampBytes[1], Length(TimeStampBytes));

        FillChar(cabTimeStamp, SizeOf(CRYPT_ATTR_BLOB), #0);
        cabTimeStamp.cbData := TimeStampStream.Size;
        cabTimeStamp.pbData := TimeStampStream.Memory;
        caTimeStamp.pszObjId := '1.2.840.113549.1.9.16.2.14';
        caTimeStamp.cValue := 1;
        caTimeStamp.rgValue := @cabTimeStamp;

        CryptCheck(CryptEncodeObject(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, PKCS_ATTRIBUTE, @caTimeStamp, nil, encodedAttributeSize), 'CryptEncodeObject');
        encodedAttribute.Size := encodedAttributeSize;
        CryptCheck(CryptEncodeObject(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, PKCS_ATTRIBUTE, @caTimeStamp, encodedAttribute.Memory, encodedAttributeSize), 'CryptEncodeObject');
        encodedAttribute.Size := encodedAttributeSize;

        unauthenticatedParam.cbSize := SizeOf(CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA);
        unauthenticatedParam.dwSignerIndex := 0; //only have 1 cert
        unauthenticatedParam.blob.cbData := encodedAttributeSize;
        unauthenticatedParam.blob.pbData := encodedAttribute.Memory;

        CryptCheck(CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, @unauthenticatedParam), 'CryptMsgControl');
        encodedMessageLength := 0;
        CryptCheck(CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, nil, encodedMessageLength), 'CryptMsgGetParam');
        pData.Size := encodedMessageLength;
        CryptCheck(CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, pData.Memory, encodedMessageLength), 'CryptMsgGetParam');
        pData.Size := encodedMessageLength;
        StreamOut.Clear;
        StreamOut.CopyFrom(pData, 0);
      end;
    end;
  finally
    pbSignedMessage.Free;
    encodedAttribute.Free;
    pData.Free;
    TimeStampStream.Free;
    SignStream.Free;
    pbDigestSize.Free;
    if hMsg <> nil then
      CryptMsgClose(hMsg);
  end;
end;

procedure SignFile(SignerCert: PCCERT_CONTEXT; FileName: string; StreamOut: TMemoryStream; DetachedSign: boolean; TSPUrl: AnsiString);
var
  FS: TMemoryStream;
begin
  FS := TMemoryStream.Create();
  try
    FS.LoadFromFile(filename);
    SignStream(SignerCert, FS, StreamOut, DetachedSign, TSPUrl);
  finally
    FS.Free;
  end;
end;


procedure SignFileSimple(SignerCert: PCCERT_CONTEXT; FileName: string; DetachedSign: boolean; TSPUrl: String);
var
  FS: TMemoryStream;
begin
  FS := TMemoryStream.Create();
  try
    SignFile(SignerCert, FileName, FS, DetachedSign, TSPUrl);
    FS.SaveToFile(FileName + '.sig');
  finally
    FS.Free;
  end;
end;


end.
