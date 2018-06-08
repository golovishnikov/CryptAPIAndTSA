{
  Author: Alexandr Mikhnevich aka ArhangeL
  www: http://arhangelsoft.ru/
  mail: mail@arhangelsoft.ru

  Description:
  THTTPSendEx class are based on Synapse ARARAT library where THTTPSend
  is a parent class of it.

  IMPORTANT!! For working you need to install this libraries:
  Synapse library - http://www.ararat.cz/synapse/doku.php/download/
  New features:
  * Many several methods for GET, POST requests.
  * File downloading methods.
  * Events HTTPWorkBegin, HTTPWork, HTTPWorkEnd
  for viewing send/recv data(like file transfer with ProgressBar).
  While transfering you will be get info about:
  - File size: Total size, transfered bytes
  - Transfer speed
  - Transfer time left
}

{
  ToDo:
  1. GZIP support
  2. URL Encode, Decode for UNICODE

  Requires:
  - Synapse library - you can found it here:  http://www.ararat.cz/synapse/doku.php/download

  -- HISTORY --

  - version 0.0.7
  [new] First public release

  - version 0.0.8
  [New] Added property as event wrapper for default event of THTTPSend.Socket.OnStatus
  allows you do your own actions on sock actions
  [Fix] Improved constructor, if input parametrs isn't assigned,
  default values will be used.
  [Fix] In GET requests custom headers was dropped before sending.
  [Fix] In GET requests HEAD request is called before GET, now this is disabled(will be used in future).
  [Improved] WriteStr2Stream in THTTPSendEx now works without TStringStream.

  - Version 0.0.9
  [Fix] POST Methods automatically calls TMultipartfomdataStream.DataEnd at start.
  No need doing that manually.
  [Fix] POST methods doesn't set mime-type "application/x-www-form-urlencoded" in some moments.
  [Fix] POST methods doesn't format TStrings in valid format for transfering.
  [Added] "POSTResponce" POST method without params for sending.
  [Changed] Property "Location" now avaliable for writing
  [Fix] Method "Clear" and "ClearAll" conflicts with "location" property.
  [Fix] Some language mistakes in the names.
  [Added] GZIP compression supported.
  [Added] Delphi 2009 and below versions are supported.
  [Added] Lazarus supported(except GZIP compression).

  // v0.0.1.0
  [Added] PUT method implemented(Works like POST)
  [Changed] HTTPMethodPOST and HTTPMethodGET moved to private section
  [Changed] "POSTResponce" renamed to "POSTWithResponce"
  [Removed] Function "URLIsDead" removed, use URLIsAlive instead.
  [Fix] In some reassons Document stream doesn't load decompressed GZIP in-traffic.
}

unit clHTTPSendEx;

interface

{$INCLUDE jedi.inc}

uses
{$IFDEF DELPHIXE2_UP}
  Winapi.Windows, System.Classes, System.SysUtils, System.StrUtils,
{$ELSE}
    Windows, Classes, SysUtils, StrUtils,
{$ENDIF}
  synsock,
  synautil, blcksock, httpsend, ssl_openssl, synacode, Registry, MISGZIPUtil,
  RegisteredFiles, CommonMIS, ConstsMIS, Log4D, PJSysInfo;

const
  HTTPVer_0_9  = '0.9';
  HTTPVer_1_0  = '1.0';
  HTTPVer_1_1  = '1.1';
  DefUserAgent = 'Mozilla/5.0 (Windows NT 6.1; rv:17.0) Gecko/17.0 Firefox/17.0';

type
  THTTPWorkBegin = procedure(Sender: TObject; aWorkCountMax: Int64;
    const IAmWriting: Boolean = False) of object;

  THTTPWork = procedure(Sender: TObject; aWorkCountMax, aWorkCount, aWorkSpeed,
    aWorkTimeLeft: Int64; const IAmWriting: Boolean = False) of object;

  THTTPWorkEnd = procedure(Sender: TObject) of object;

type
  TMultipartFormDataStream = class(TObject)
  private
    fBound: string;
    fBoundStr: string;
    fClosed: Boolean;
    function GetMimeProp: string;
  protected
    fStream: TStringStream;
  public
    function GetFileMIMEType(const aFile: string): string;
    procedure AddFieldString(aFieldName: string; aValue: string);
    procedure AddFieldInteger(aFieldName: string; aValue: Integer);
    procedure AddFieldFloat(aFieldName: string; aValue: Extended);
    procedure AddFieldBool(aFieldName: string; aValue: Boolean;
      const cUseBoolStrs: Boolean = False);
    procedure AddFile(aFieldName: string; aFile: string); overload;
    procedure AddFile(aFieldName, aFileName: string; aFileContent: TStream); overload;
    property Stream: TStringStream read fStream write fStream;
    property MIMEType: string read GetMimeProp;
    property IsClosed: Boolean read fClosed;
    procedure DataEnd;
    constructor Create;
    destructor Destroy; override;
  end;

type
  THTTPSendEx = class(THTTPSend)
  private
    fGZIPAllowed: Boolean;
    fGZIPMinimumSize: Cardinal;
    fOnWorkBegin: THTTPWorkBegin;
    fOnWork: THTTPWork;
    fOnWorkEnd: THTTPWorkEnd;
    fOnStatus: THookSocketStatus;
    fURL: string;
    function GetRespCode: Integer;
    function GetRespStr: string;
    function GetDataLength: Int64;
    // General HET/POST IN/OUT
    function HTTPMethodPOST(const aURL: string; aMethodReplacer: string = ''): Boolean;

    function HTTPMethodGET(const aURL: string): Boolean;

    procedure SetBasicAuthorization;
  protected
    fLocation: string; // for 301 & 302

    // Distance
    fWork_WorkSizeBegin: Int64;
    fWork_WorkSizeCurrent: Int64;

    // Time
    fWork_TimeStart: Int64;
    fWork_TimeEnd: Int64;
    fWork_TimeCurrent: Int64;
    fWork_TimeLeft: Int64;
    // Time packet recv/send frame
    fWork_TimeFrameStart: Int64;
    fWork_TimeFrameBetween: Int64;
    fWork_TimeFrameEnd: Int64;

    // speed
    fWork_SpeedCurrent: Int64;
    FBasicAuth: string;
    FLogger: TLogLogger;

    procedure HTTPOnStatus(Sender: TObject; Reason: THookSocketReason;
      const Value: string);
    procedure SetWorkBegin(aWorkCountMax: Int64; const IAmWriting: Boolean = False);

    procedure SetWork(aWorkCountMax, aWorkCount, aWorkSpeed, aWorkTimeLeft: Int64;
      const IAmWriting: Boolean = False);

    procedure SetWorkEnd;
    function GetIsRedirect: Boolean;
    function GetIsSuccessfull: Boolean;
    function GetIsntFound: Boolean;

    procedure HookStatus(Sender: TObject; Reason: THookSocketReason; const Value: string);
    procedure HookMonitor(Sender: TObject; Writing: Boolean; const Buffer: TMemory; Len: Integer);
  public
    // Props
    property Location: string read fLocation write fLocation;
    property IsRedirect: Boolean read GetIsRedirect;
    property IsSuccessfull: Boolean read GetIsSuccessfull;
    property IsntFound: Boolean read GetIsntFound;
    property ResponseCode: Integer read GetRespCode;
    property ResponseString: string read GetRespStr;
    property GZIPAllowed: Boolean read fGZIPAllowed write fGZIPAllowed;
    property GZIPMinimumSize: Cardinal read fGZIPMinimumSize write fGZIPMinimumSize;
    property URL: string read fURL;
    // Events
    property OnWorkBegin: THTTPWorkBegin read fOnWorkBegin write fOnWorkBegin;
    property OnWork: THTTPWork read fOnWork write fOnWork;
    property OnWorkEnd: THTTPWorkEnd read fOnWorkEnd write fOnWorkEnd;
    property OnSocketStatus: THookSocketStatus read fOnStatus write fOnStatus;

    // PUT
    function PUT(sURL: string; aStream: TStream; out sResponseStr: string): Boolean;

    // DELETE
    function DELETE(sURL: string): Boolean; overload;

    // GET
    function HEAD(sURL: string): Boolean;

    function GET(sURL: string): Boolean; overload;

    function GET(sURL: string; out aResponseStr: string): Boolean; overload;

    function GET(sURL: string; const sResponseStream: TStream): Boolean; overload;
    // GET \\

    // POST
    function POST(sURL: string): Boolean; overload;

    function POST(sURL: string; sParams: string): Boolean; overload;

    function POST(sURL: string; sParams: TStrings): Boolean; overload;

    function POST(sURL: string; sParams: TStream): Boolean; overload;

    function POSTWithResponce(sURL: string; out sResponseStr: string): Boolean; overload;

    function POST(sURL: string; sParams: string; out sResponseStr: string)
      : Boolean; overload;

    function POST(sURL: string; sParams: string; const sResponseStream: TStream)
      : Boolean; overload;

    function POST(sURL: string; sParams: TStrings; out sResponseStr: string)
      : Boolean; overload;

    function POST(sURL: string; sParams: TStrings; const sResponseStream: TStream)
      : Boolean; overload;

    function POST(sURL: string; sParams: TStream; out sResponseStr: string)
      : Boolean; overload;

    function POST(sURL: string; sParams: TStream; const sResponseStream: TStream)
      : Boolean; overload;

    function POST(sURL: string; sData: TMultipartFormDataStream; out sResponseStr: string)
      : Boolean; overload;

    function POST(sURL: string; sData: TMultipartFormDataStream;
      const sResponseStream: TStream): Boolean; overload;

    // POST \\

    function URLIsAlive(const aURL: string): Boolean;

    procedure WriteStr2Stream(aStr: string);
    procedure ClearAll;

    function DownloadFile(const aURL: string; aSavePath: string): Boolean;
    function DownloadFileToTemp(const aURL: string; var sOutFile: string): Boolean;

    procedure SetBasicAuth(const AUser, APassword: string);

    // Constructors
    constructor Create; overload;

    constructor Create(const aUserAgent: string); overload;

    constructor Create(const aUserAgent: string;
      const sHTTPVersion: string = HTTPVer_1_1); overload;

    destructor Destroy; override;

  published

    property Headers;
    property Cookies;
    property ResultCode;
    property ResultString;
    property Document;
  end;

function GetFileMIMEType(const aFile: string): string;

implementation

{ COMMON }

const
  BASIC_AUTH_PREFIX = 'Authorization: Basic ';
var
  MIMETypeCache: TStringList;

procedure LoadMIMETypeCache(MTL: TStrings);
var
  reg: TRegistry;
  KeyList: TStringList;
  i: Integer;
  s: String;
begin
  if not Assigned(MIMETypeCache) then
  begin
    MIMETypeCache := TStringList.Create;
    with MIMETypeCache do
    begin
      Add('.nml=animation/narrative');
      Add('.aac=audio/mp4');
      Add('.aif=audio/x-aiff');
      Add('.aifc=audio/x-aiff');
      Add('.aiff=audio/x-aiff');
      Add('.au=audio/basic');
      Add('.gsm=audio/x-gsm');
      Add('.kar=audio/midi');
      Add('.m3u=audio/mpegurl');
      Add('.m4a=audio/x-mpg');
      Add('.mid=audio/midi');
      Add('.midi=audio/midi');
      Add('.mpega=audio/x-mpg');
      Add('.mp2=audio/x-mpg');
      Add('.mp3=audio/x-mpg');
      Add('.mpga=audio/x-mpg');
      Add('.m3u=audio/x-mpegurl');
      Add('.pls=audio/x-scpls');
      Add('.qcp=audio/vnd.qcelp');
      Add('.ra=audio/x-realaudio');
      Add('.ram=audio/x-pn-realaudio');
      Add('.rm=audio/x-pn-realaudio');
      Add('.sd2=audio/x-sd2');
      Add('.sid=audio/prs.sid');
      Add('.snd=audio/basic');
      Add('.wav=audio/x-wav');
      Add('.wax=audio/x-ms-wax');
      Add('.wma=audio/x-ms-wma');
      Add('.mjf=audio/x-vnd.AudioExplosion.MjuiceMediaFile');
      Add('.art=image/x-jg');
      Add('.bmp=image/bmp');
      Add('.cdr=image/x-coreldraw');
      Add('.cdt=image/x-coreldrawtemplate');
      Add('.cpt=image/x-corelphotopaint');
      Add('.djv=image/vnd.djvu');
      Add('.djvu=image/vnd.djvu');
      Add('.gif=image/gif');
      Add('.ief=image/ief');
      Add('.ico=image/x-icon');
      Add('.jng=image/x-jng');
      Add('.jpg=image/jpeg');
      Add('.jpeg=image/jpeg');
      Add('.jpe=image/jpeg');
      Add('.pat=image/x-coreldrawpattern');
      Add('.pcx=image/pcx');
      Add('.pbm=image/x-portable-bitmap');
      Add('.pgm=image/x-portable-graymap');
      Add('.pict=image/x-pict');
      Add('.png=image/x-png');
      Add('.pnm=image/x-portable-anymap');
      Add('.pntg=image/x-macpaint');
      Add('.ppm=image/x-portable-pixmap');
      Add('.psd=image/x-psd');
      Add('.qtif=image/x-quicktime');
      Add('.ras=image/x-cmu-raster');
      Add('.rf=image/vnd.rn-realflash');
      Add('.rgb=image/x-rgb');
      Add('.rp=image/vnd.rn-realpix');
      Add('.sgi=image/x-sgi');
      Add('.svg=image/svg-xml');
      Add('.svgz=image/svg-xml');
      Add('.targa=image/x-targa');
      Add('.tif=image/x-tiff');
      Add('.wbmp=image/vnd.wap.wbmp');
      Add('.webp=image/webp');
      Add('.xbm=image/xbm');
      Add('.xbm=image/x-xbitmap');
      Add('.xpm=image/x-xpixmap');
      Add('.xwd=image/x-xwindowdump');
      Add('.323=text/h323');
      Add('.xml=text/xml');
      Add('.uls=text/iuls');
      Add('.txt=text/plain');
      Add('.rtx=text/richtext');
      Add('.wsc=text/scriptlet');
      Add('.rt=text/vnd.rn-realtext');
      Add('.htt=text/webviewhtml');
      Add('.htc=text/x-component');
      Add('.vcf=text/x-vcard');
      Add('.asf=video/x-ms-asf');
      Add('.asx=video/x-ms-asf');
      Add('.avi=video/x-msvideo');
      Add('.dl=video/dl');
      Add('.dv=video/dv');
      Add('.flc=video/flc');
      Add('.fli=video/fli');
      Add('.gl=video/gl');
      Add('.lsf=video/x-la-asf');
      Add('.lsx=video/x-la-asf');
      Add('.mng=video/x-mng');
      Add('.mp2=video/mpeg');
      Add('.mp3=video/mpeg');
      Add('.mp4=video/mpeg');
      Add('.mpeg=video/x-mpeg2a');
      Add('.mpa=video/mpeg');
      Add('.mpe=video/mpeg');
      Add('.mpg=video/mpeg');
      Add('.ogv=video/ogg');
      Add('.moov=video/quicktime');
      Add('.mov=video/quicktime');
      Add('.mxu=video/vnd.mpegurl');
      Add('.qt=video/quicktime');
      Add('.qtc=video/x-qtc'); { Do not loccalize }
      Add('.rv=video/vnd.rn-realvideo');
      Add('.ivf=video/x-ivf');
      Add('.webm=video/webm');
      Add('.wm=video/x-ms-wm');
      Add('.wmp=video/x-ms-wmp');
      Add('.wmv=video/x-ms-wmv');
      Add('.wmx=video/x-ms-wmx');
      Add('.wvx=video/x-ms-wvx');
      Add('.rms=video/vnd.rn-realvideo-secure');
      Add('.asx=video/x-ms-asf-plugin');
      Add('.movie=video/x-sgi-movie');
      Add('.7z=application/x-7z-compressed');
      Add('.a=application/x-archive');
      Add('.aab=application/x-authorware-bin');
      Add('.aam=application/x-authorware-map');
      Add('.aas=application/x-authorware-seg');
      Add('.abw=application/x-abiword');
      Add('.ace=application/x-ace-compressed');
      Add('.ai=application/postscript');
      Add('.alz=application/x-alz-compressed');
      Add('.ani=application/x-navi-animation');
      Add('.arj=application/x-arj');
      Add('.asf=application/vnd.ms-asf');
      Add('.bat=application/x-msdos-program');
      Add('.bcpio=application/x-bcpio');
      Add('.boz=application/x-bzip2');
      Add('.bz=application/x-bzip');
      Add('.bz2=application/x-bzip2');
      Add('.cab=application/vnd.ms-cab-compressed');
      Add('.cat=application/vnd.ms-pki.seccat');
      Add('.ccn=application/x-cnc');
      Add('.cco=application/x-cocoa');
      Add('.cdf=application/x-cdf');
      Add('.cer=application/x-x509-ca-cert');
      Add('.chm=application/vnd.ms-htmlhelp');
      Add('.chrt=application/vnd.kde.kchart');
      Add('.cil=application/vnd.ms-artgalry');
      Add('.class=application/java-vm');
      Add('.com=application/x-msdos-program');
      Add('.clp=application/x-msclip');
      Add('.cpio=application/x-cpio');
      Add('.cpt=application/mac-compactpro');
      Add('.cqk=application/x-calquick');
      Add('.crd=application/x-mscardfile');
      Add('.crl=application/pkix-crl');
      Add('.csh=application/x-csh');
      Add('.dar=application/x-dar');
      Add('.dbf=application/x-dbase');
      Add('.dcr=application/x-director');
      Add('.deb=application/x-debian-package');
      Add('.dir=application/x-director');
      Add('.dist=vnd.apple.installer+xml');
      Add('.distz=vnd.apple.installer+xml');
      Add('.dll=application/x-msdos-program');
      Add('.dmg=application/x-apple-diskimage');
      Add('.doc=application/msword');
      Add('.dot=application/msword');
      Add('.dvi=application/x-dvi');
      Add('.dxr=application/x-director');
      Add('.ebk=application/x-expandedbook');
      Add('.eps=application/postscript');
      Add('.evy=application/envoy');
      Add('.exe=application/x-msdos-program');
      Add('.fdf=application/vnd.fdf');
      Add('.fif=application/fractals');
      Add('.flm=application/vnd.kde.kivio');
      Add('.fml=application/x-file-mirror-list');
      Add('.gzip=application/x-gzip');
      Add('.gnumeric=application/x-gnumeric');
      Add('.gtar=application/x-gtar');
      Add('.gz=application/x-gzip');
      Add('.hdf=application/x-hdf');
      Add('.hlp=application/winhlp');
      Add('.hpf=application/x-icq-hpf');
      Add('.hqx=application/mac-binhex40');
      Add('.hta=application/hta');
      Add('.ims=application/vnd.ms-ims');
      Add('.ins=application/x-internet-signup');
      Add('.iii=application/x-iphone');
      Add('.iso=application/x-iso9660-image');
      Add('.jar=application/java-archive');
      Add('.karbon=application/vnd.kde.karbon');
      Add('.kfo=application/vnd.kde.kformula');
      Add('.kon=application/vnd.kde.kontour');
      Add('.kpr=application/vnd.kde.kpresenter');
      Add('.kpt=application/vnd.kde.kpresenter');
      Add('.kwd=application/vnd.kde.kword');
      Add('.kwt=application/vnd.kde.kword');
      Add('.latex=application/x-latex');
      Add('.lha=application/x-lzh');
      Add('.lcc=application/fastman');
      Add('.lrm=application/vnd.ms-lrm');
      Add('.lz=application/x-lzip');
      Add('.lzh=application/x-lzh');
      Add('.lzma=application/x-lzma');
      Add('.lzo=application/x-lzop');
      Add('.lzx=application/x-lzx');
      Add('.m13=application/x-msmediaview');
      Add('.m14=application/x-msmediaview');
      Add('.mpp=application/vnd.ms-project');
      Add('.mvb=application/x-msmediaview');
      Add('.man=application/x-troff-man');
      Add('.mdb=application/x-msaccess');
      Add('.me=application/x-troff-me');
      Add('.ms=application/x-troff-ms');
      Add('.msi=application/x-msi');
      Add('.mpkg=vnd.apple.installer+xml');
      Add('.mny=application/x-msmoney');
      Add('.nix=application/x-mix-transfer');
      Add('.o=application/x-object');
      Add('.oda=application/oda');
      Add('.odb=application/vnd.oasis.opendocument.database');
      Add('.odc=application/vnd.oasis.opendocument.chart');
      Add('.odf=application/vnd.oasis.opendocument.formula');
      Add('.odg=application/vnd.oasis.opendocument.graphics');
      Add('.odi=application/vnd.oasis.opendocument.image');
      Add('.odm=application/vnd.oasis.opendocument.text-master');
      Add('.odp=application/vnd.oasis.opendocument.presentation');
      Add('.ods=application/vnd.oasis.opendocument.spreadsheet');
      Add('.ogg=application/ogg');
      Add('.odt=application/vnd.oasis.opendocument.text');
      Add('.otg=application/vnd.oasis.opendocument.graphics-template');
      Add('.oth=application/vnd.oasis.opendocument.text-web');
      Add('.otp=application/vnd.oasis.opendocument.presentation-template');
      Add('.ots=application/vnd.oasis.opendocument.spreadsheet-template');
      Add('.ott=application/vnd.oasis.opendocument.text-template');
      Add('.p10=application/pkcs10');
      Add('.p12=application/x-pkcs12');
      Add('.p7b=application/x-pkcs7-certificates');
      Add('.p7m=application/pkcs7-mime');
      Add('.p7r=application/x-pkcs7-certreqresp');
      Add('.p7s=application/pkcs7-signature');
      Add('.package=application/vnd.autopackage');
      Add('.pfr=application/font-tdpfr');
      Add('.pkg=vnd.apple.installer+xml');
      Add('.pdf=application/pdf');
      Add('.pko=application/vnd.ms-pki.pko');
      Add('.pl=application/x-perl');
      Add('.pnq=application/x-icq-pnq');
      Add('.pot=application/mspowerpoint');
      Add('.pps=application/mspowerpoint');
      Add('.ppt=application/mspowerpoint');
      Add('.ppz=application/mspowerpoint');
      Add('.ps=application/postscript');
      Add('.pub=application/x-mspublisher');
      Add('.qpw=application/x-quattropro');
      Add('.qtl=application/x-quicktimeplayer');
      Add('.rar=application/rar');
      Add('.rdf=application/rdf+xml');
      Add('.rjs=application/vnd.rn-realsystem-rjs');
      Add('.rm=application/vnd.rn-realmedia');
      Add('.rmf=application/vnd.rmf');
      Add('.rmp=application/vnd.rn-rn_music_package');
      Add('.rmx=application/vnd.rn-realsystem-rmx');
      Add('.rnx=application/vnd.rn-realplayer');
      Add('.rpm=application/x-redhat-package-manager');
      Add('.rsml=application/vnd.rn-rsml');
      Add('.rtsp=application/x-rtsp');
      Add('.rss=application/rss+xml');
      Add('.scm=application/x-icq-scm');
      Add('.ser=application/java-serialized-object');
      Add('.scd=application/x-msschedule');
      Add('.sda=application/vnd.stardivision.draw');
      Add('.sdc=application/vnd.stardivision.calc');
      Add('.sdd=application/vnd.stardivision.impress');
      Add('.sdp=application/x-sdp');
      Add('.setpay=application/set-payment-initiation');
      Add('.setreg=application/set-registration-initiation');
      Add('.sh=application/x-sh');
      Add('.shar=application/x-shar');
      Add('.shw=application/presentations');
      Add('.sit=application/x-stuffit');
      Add('.sitx=application/x-stuffitx');
      Add('.skd=application/x-koan');
      Add('.skm=application/x-koan');
      Add('.skp=application/x-koan');
      Add('.skt=application/x-koan');
      Add('.smf=application/vnd.stardivision.math');
      Add('.smi=application/smil');
      Add('.smil=application/smil');
      Add('.spl=application/futuresplash');
      Add('.ssm=application/streamingmedia');
      Add('.sst=application/vnd.ms-pki.certstore');
      Add('.stc=application/vnd.sun.xml.calc.template');
      Add('.std=application/vnd.sun.xml.draw.template');
      Add('.sti=application/vnd.sun.xml.impress.template');
      Add('.stl=application/vnd.ms-pki.stl');
      Add('.stw=application/vnd.sun.xml.writer.template');
      Add('.svi=application/softvision');
      Add('.sv4cpio=application/x-sv4cpio');
      Add('.sv4crc=application/x-sv4crc');
      Add('.swf=application/x-shockwave-flash');
      Add('.swf1=application/x-shockwave-flash');
      Add('.sxc=application/vnd.sun.xml.calc');
      Add('.sxi=application/vnd.sun.xml.impress');
      Add('.sxm=application/vnd.sun.xml.math');
      Add('.sxw=application/vnd.sun.xml.writer');
      Add('.sxg=application/vnd.sun.xml.writer.global');
      Add('.t=application/x-troff');
      Add('.tar=application/x-tar');
      Add('.tcl=application/x-tcl');
      Add('.tex=application/x-tex');
      Add('.texi=application/x-texinfo');
      Add('.texinfo=application/x-texinfo');
      Add('.tbz=application/x-bzip-compressed-tar');
      Add('.tbz2=application/x-bzip-compressed-tar');
      Add('.tgz=application/x-compressed-tar');
      Add('.tlz=application/x-lzma-compressed-tar');
      Add('.tr=application/x-troff');
      Add('.trm=application/x-msterminal');
      Add('.troff=application/x-troff');
      Add('.tsp=application/dsptype');
      Add('.torrent=application/x-bittorrent');
      Add('.ttz=application/t-time');
      Add('.txz=application/x-xz-compressed-tar');
      Add('.udeb=application/x-debian-package');
      Add('.uin=application/x-icq');
      Add('.urls=application/x-url-list');
      Add('.ustar=application/x-ustar');
      Add('.vcd=application/x-cdlink');
      Add('.vor=application/vnd.stardivision.writer');
      Add('.vsl=application/x-cnet-vsl');
      Add('.wcm=application/vnd.ms-works');
      Add('.wb1=application/x-quattropro');
      Add('.wb2=application/x-quattropro');
      Add('.wb3=application/x-quattropro');
      Add('.wdb=application/vnd.ms-works');
      Add('.wks=application/vnd.ms-works');
      Add('.wmd=application/x-ms-wmd');
      Add('.wms=application/x-ms-wms');
      Add('.wmz=application/x-ms-wmz');
      Add('.wp5=application/wordperfect5.1');
      Add('.wpd=application/wordperfect');
      Add('.wpl=application/vnd.ms-wpl');
      Add('.wps=application/vnd.ms-works');
      Add('.wri=application/x-mswrite');
      Add('.xfdf=application/vnd.adobe.xfdf');
      Add('.xls=application/x-msexcel');
      Add('.xlb=application/x-msexcel');
      Add('.xpi=application/x-xpinstall');
      Add('.xps=application/vnd.ms-xpsdocument');
      Add('.xsd=application/vnd.sun.xml.draw');
      Add('.xul=application/vnd.mozilla.xul+xml');
      Add('.z=application/x-compress');
      Add('.zoo=application/x-zoo');
      Add('.zip=application/x-zip-compressed');
      Add('.wbmp=image/vnd.wap.wbmp');
      Add('.wml=text/vnd.wap.wml');
      Add('.wmlc=application/vnd.wap.wmlc');
      Add('.wmls=text/vnd.wap.wmlscript');
      Add('.wmlsc=application/vnd.wap.wmlscriptc');
      Add('.asm=text/x-asm');
      Add('.p=text/x-pascal');
      Add('.pas=text/x-pascal');
      Add('.cs=text/x-csharp');
      Add('.c=text/x-csrc');
      Add('.c++=text/x-c++src');
      Add('.cpp=text/x-c++src');
      Add('.cxx=text/x-c++src');
      Add('.cc=text/x-c++src');
      Add('.h=text/x-chdr');
      Add('.h++=text/x-c++hdr');
      Add('.hpp=text/x-c++hdr');
      Add('.hxx=text/x-c++hdr');
      Add('.hh=text/x-c++hdr');
      Add('.java=text/x-java');
      Add('.css=text/css');
      Add('.js=text/javascript');
      Add('.htm=text/html');
      Add('.html=text/html');
      Add('.xhtml=application/xhtml+xml');
      Add('.xht=application/xhtml+xml');
      Add('.rdf=application/rdf+xml');
      Add('.rss=application/rss+xml');
      Add('.ls=text/javascript');
      Add('.mocha=text/javascript');
      Add('.shtml=server-parsed-html');
      Add('.xml=text/xml');
      Add('.sgm=text/sgml');
      Add('.sgml=text/sgml');
    end;

    Reg := TRegistry.Create;
    try
      KeyList := TStringList.create;
      try
        Reg.RootKey := HKEY_CLASSES_ROOT;
        if Reg.OpenKeyreadOnly('\MIME\Database\Content Type') then {do not localize}
        begin
          // get a list of registered MIME types
          KeyList.Clear;

          Reg.GetKeyNames(KeyList);
          for i := 0 to KeyList.Count - 1 do
          begin
            if Reg.OpenKeyreadOnly('\MIME\Database\Content Type\' + KeyList[i]) then {do not localize}
            begin
              s := reg.ReadString('Extension');  {do not localize}
              if (Length(s)>0) then
                MIMETypeCache.Values[s] := KeyList[i];
            end;
          end;
        end;
        
        if Reg.OpenKeyReadOnly('\') then  {do not localize}
        begin
          Reg.GetKeyNames(KeyList);
        end;
        // get a list of registered extentions
        for i := 0 to KeyList.Count - 1 do
        begin
          if Copy(KeyList[i], 1, 1) = '.' then   {do not localize}
          begin
            if reg.OpenKeyReadOnly('\' + KeyList[i]) then
            begin
              s := Reg.ReadString('Content Type');  {do not localize}
              if Length(s) > 0 then
              begin
                MIMETypeCache.Values[KeyList[i]] := s;
              end;
            end;
          end;
        end;
      finally
        KeyList.Free;
      end;
    finally
      reg.free;
    end;

  end;
  MTL.AddStrings(MIMETypeCache);
end;

function GetFileMIMEType(const aFile: string): string;
var
  sFileExt: String;
  sResult: String;
  MT: TStringList;
begin
  sFileExt := LowerCase(ExtractFileExt(aFile));
  sResult := EmptyStr;
  if sFileExt<>EmptyStr then
  begin
    MT := TStringList.Create;
    try
      LoadMIMETypeCache(MT);
      sResult := MT.Values[sFileExt];
    finally
      FreeAndNil(MT);
    end;
  end;
  if sResult<>EmptyStr then
    Result := sResult
  else
    Result := 'application/octet-stream';
end;

function PreprocessStrings(aStrings: TStrings): string;
var
  i: Integer;
begin
  if (aStrings.Count > 1) then
  begin
    for i := 1 to aStrings.Count - 1 do
      aStrings[i] := '&' + aStrings[i];
  end;
  Result := StringReplace(aStrings.Text, #$D#$A, '', [rfReplaceAll, rfIgnoreCase]);
end;

{ THTTPSendEx }

procedure THTTPSendEx.WriteStr2Stream(aStr: string);
{$IFDEF DELPHIXE_UP}
var
  Buff: TBytes;
{$ENDIF}
begin
{$IFDEF DELPHIXE_UP}
  Buff := BytesOf(aStr);
  Document.Write(Buff, Length(Buff));
{$ELSE}
  synautil.WriteStrToStream(Document, aStr);
{$ENDIF}
end;

procedure THTTPSendEx.ClearAll;
begin
  Clear;
  Cookies.Clear;
end;

constructor THTTPSendEx.Create(const aUserAgent: string);
begin
  Create;
  Protocol := HTTPVer_1_1;
  if not(aUserAgent = EmptyStr) then
    UserAgent := aUserAgent;
end;

constructor THTTPSendEx.Create;
begin
  inherited Create;
  Protocol := HTTPVer_1_1;
  UserAgent := 'MIS/1.0 ('+TPJOSInfo.Description+')';
  fGZIPAllowed := True;
  fGZIPMinimumSize := 5120; // bytes
  FLogger := TLogLogger.GetLogger(Self.ClassName);
  if FLogger.IsDebugEnabled then
  begin
    Sock.OnStatus := HookStatus;
    Sock.OnMonitor := HookMonitor;
  end
  else
  begin
    Sock.OnStatus := HTTPOnStatus;
  end;

end;

constructor THTTPSendEx.Create(const aUserAgent: string; const sHTTPVersion: string);
begin
  Create;
  if not(aUserAgent = EmptyStr) then
    UserAgent := aUserAgent;
  if not(sHTTPVersion = EmptyStr) then
    Protocol := sHTTPVersion;
end;

function THTTPSendEx.DELETE(sURL: string): Boolean;
begin
  Result := HTTPMethodPOST(sURL, 'DELETE');
end;

destructor THTTPSendEx.Destroy;
begin
  //
  inherited;
end;

function THTTPSendEx.DownloadFileToTemp(const aURL: string; var sOutFile: string)
  : Boolean;
var
  Buff, fBuff: array [0 .. MAX_PATH] of Char;
begin
  GetTempPath(Length(Buff), @Buff);
  GetTempFileName(@Buff, '.~tmp', Random(DateTimeToFileDate(Now)), @fBuff);
  sOutFile := fBuff;
  Result := DownloadFile(aURL, sOutFile);
  SetFileattributes(@fBuff, GetFileAttributes(@fBuff) or FILE_ATTRIBUTE_TEMPORARY);
end;

function THTTPSendEx.DownloadFile(const aURL: string; aSavePath: string): Boolean;
var
  FS: TFileStream;
begin
  FS := TFileStream.Create(aSavePath, fmCreate or fmOpenWrite or fmShareDenyWrite);
  try
    Result := GET(aURL, FS);
  finally
    FreeAndNil(FS);
  end;
end;

function THTTPSendEx.HTTPMethodGET(const aURL: string): Boolean;
var
  MemStream: TMemoryStream;
  bOK: Boolean;
begin
  fURL := aURL;
  fWork_WorkSizeBegin := 0;
  fWork_WorkSizeCurrent := 0;
  fWork_TimeStart := 0;
  fWork_TimeLeft := 0;
  fWork_TimeEnd := 0;
  fWork_TimeCurrent := 0;
  fWork_SpeedCurrent := 0;
  // HEAD(aURL);
  fWork_WorkSizeBegin := GetDataLength;
  // Clear;
  SetBasicAuthorization;
  if (MIMEType = EmptyStr) or (MIMEType = 'application/x-www-form-urlencoded') then
    MIMEType := 'text/html'; // It's default
  bOK := True;
  MemStream := TMemoryStream.Create;
  try

    if fGZIPAllowed then
      Headers.Add('Accept-Encoding: gzip');
    fWork_TimeStart := GetTickCount;
    SetWorkBegin(fWork_WorkSizeBegin, False);
    Result := HTTPMethod('GET', aURL);
    if GetIsRedirect then
    begin
      Headers.NameValueSeparator := ':';
      fLocation := Trim(Headers.Values['Location']);
      Headers.NameValueSeparator := '=';
    end
    else
      fLocation := '';
    fWork_TimeEnd := GetTickCount;
    if fGZIPAllowed and (Pos('content-encoding: gzip', LowerCase(Headers.Text)) > 0) then
    begin
      try
        GZDecompressStream(Document, MemStream);
      except
        bOK := False;
      end;

      if bOK then
      begin
        Document.Clear;
        Document.LoadFromStream(MemStream);
      end;
    end;
    SetWorkEnd;
  finally
    FreeAndNil(MemStream);
    fURL := '';
  end;
end;

function THTTPSendEx.HTTPMethodPOST(const aURL: string;
  aMethodReplacer: string = ''): Boolean;
var
  MemStream: TMemoryStream;
  bOK: Boolean;
begin
  fURL := aURL;
  fWork_WorkSizeBegin := 0;
  fWork_WorkSizeCurrent := 0;
  fWork_TimeStart := 0;
  fWork_TimeLeft := 0;
  fWork_TimeEnd := 0;
  fWork_TimeCurrent := 0;
  fWork_SpeedCurrent := 0;
  SetBasicAuthorization;
  if (MIMEType = EmptyStr) or (MIMEType = 'text/html') then
    MIMEType := 'application/x-www-form-urlencoded'; // It's default
  bOK := True;
  MemStream := TMemoryStream.Create;
  try
    if fGZIPAllowed then
    begin
      Headers.Add('Accept-Encoding: gzip');
      if (Document.Size > fGZIPMinimumSize) then
      begin
        try
          GZCompressStream(Document, MemStream);
        except
          bOK := False;
        end;

        if bOK then
        begin
          Document.Clear;
          Document.LoadFromStream(MemStream);
          Headers.Add('Content-encoding: gzip');
        end;
      end;
    end;
    fWork_TimeStart := GetTickCount;
    fWork_WorkSizeBegin := Document.Size + Length(Headers.Text) + Length(Cookies.Text);
    SetWorkBegin(fWork_WorkSizeBegin, True);
    if (aMethodReplacer = EmptyStr) then
      Result := HTTPMethod('POST', aURL)
    else
      Result := HTTPMethod(aMethodReplacer, aURL);
    fWork_TimeEnd := GetTickCount;
    if fGZIPAllowed and (Pos('content-encoding: gzip', LowerCase(Headers.Text)) > 0) then
    begin
      try
        GZDecompressStream(Document, MemStream);
      except
        bOK := False;
      end;

      if bOK then
      begin
        Document.Clear;
        Document.CopyFrom(MemStream, 0);
      end;
    end;
    if GetIsRedirect then
    begin
      Headers.NameValueSeparator := ':';
      fLocation := Trim(Headers.Values['Location']);
      Headers.NameValueSeparator := '=';
    end
    else
      fLocation := '';
    SetWorkEnd;
  finally
    FreeAndNil(MemStream);
    fURL := '';
  end;
end;

procedure THTTPSendEx.HTTPOnStatus(Sender: TObject; Reason: THookSocketReason;
  const Value: string);
var
  iData: Int64;
begin
  if Assigned(fOnStatus) then
    fOnStatus(Sender, Reason, Value);

  iData := StrToInt64Def(Value, 0);
  // Distance
  fWork_WorkSizeCurrent := fWork_WorkSizeCurrent + iData;

  // Time
  fWork_TimeCurrent := GetTickCount - fWork_TimeStart;

  // Speed
  if not(fWork_TimeCurrent <= 0) then
    fWork_SpeedCurrent := fWork_WorkSizeCurrent div fWork_TimeCurrent;

  // Time left: (TotalDistance-CurrentDistance)*Curent speed
  fWork_TimeLeft := (fWork_WorkSizeBegin - fWork_WorkSizeCurrent) * fWork_SpeedCurrent;

  if (Reason = HR_ReadCount) then // GET
  begin
    SetWork(fWork_WorkSizeBegin, fWork_WorkSizeCurrent, fWork_TimeLeft,
      fWork_SpeedCurrent, True);
  end;

  if (Reason = HR_WriteCount) then // POST
  begin
    SetWork(fWork_WorkSizeBegin, fWork_WorkSizeCurrent, fWork_TimeLeft,
      fWork_SpeedCurrent, False);
  end;
end;

function THTTPSendEx.GET(sURL: string; const sResponseStream: TStream): Boolean;
begin
  Result := HTTPMethodGET(sURL);
  sResponseStream.CopyFrom(Document, 0);
end;

function THTTPSendEx.GET(sURL: string): Boolean;
begin
  Result := HTTPMethodGET(sURL);
end;

function THTTPSendEx.GET(sURL: string; out aResponseStr: string): Boolean;
var
  ss: TStringStream;
begin
  Result := HTTPMethodGET(sURL);
{$IFDEF DELPHI2009_UP}
  ss := TStringStream.Create;
{$ELSE}
  ss := TStringStream.Create('');
{$ENDIF}
  try
{$IFDEF DELPHI2009_UP}
    ss.LoadFromStream(Document);
{$ELSE}
    ss.CopyFrom(Document, 0);
{$ENDIF}
    aResponseStr := ss.DataString;

  finally
    FreeAndNil(ss);
  end;
end;

function THTTPSendEx.GetDataLength: Int64;
begin

  Headers.NameValueSeparator := ':';
  Result := StrToInt64Def(Headers.Values['Content-Length'], 0) + Length(Headers.Text);
  Headers.NameValueSeparator := '=';
end;

function THTTPSendEx.GetRespCode: Integer;
begin
  if (ResultCode = 500) and (Sock.LastError<>0) then
    Result := Sock.LastError
  else
    Result := ResultCode;
end;

function THTTPSendEx.GetRespStr: string;
begin
  if (ResultCode = 500) and (Sock.LastError<>0) then
    Result := Sock.GetErrorDescEx
  else
    Result := ResultString;
end;

function THTTPSendEx.HEAD(sURL: string): Boolean;
begin
  Clear;
  SetBasicAuthorization;
  Result := HTTPMethod('HEAD', sURL);
end;

function THTTPSendEx.GetIsntFound: Boolean;
begin
  Result := (ResponseCode = 404);
end;

function THTTPSendEx.GetIsRedirect: Boolean;
begin
  Result := (ResponseCode = 302);
end;

function THTTPSendEx.GetIsSuccessfull: Boolean;
begin
  Result := (ResponseCode = 200);
end;

function THTTPSendEx.POST(sURL: string; sParams: TStream): Boolean;
begin
  Document.Clear;
  Document.LoadFromStream(sParams);
  Result := HTTPMethodPOST(sURL);
end;

function THTTPSendEx.POST(sURL, sParams: string): Boolean;
begin
  Document.Clear;
  WriteStr2Stream(sParams);
  Result := HTTPMethodPOST(sURL);
end;

function THTTPSendEx.POST(sURL: string; sParams: TStrings): Boolean;
var
  s: string;
begin
  s := PreprocessStrings(sParams);
  Document.Clear;
  WriteStr2Stream(s);
  Result := HTTPMethodPOST(sURL);
end;

function THTTPSendEx.POST(sURL, sParams: string; out sResponseStr: string): Boolean;
var
  ss: TStringStream;
begin
  Document.Clear;
  WriteStr2Stream(sParams);
  Result := HTTPMethodPOST(sURL);
{$IFDEF DELPHI2009_UP}
  ss := TStringStream.Create;
{$ELSE}
  ss := TStringStream.Create('');
{$ENDIF}
  try
{$IFDEF DELPHI2009_UP}
    ss.LoadFromStream(Document);
{$ELSE}
    ss.CopyFrom(Document, 0);
{$ENDIF}
    sResponseStr := ss.DataString;

  finally
    FreeAndNil(ss);
  end;
end;

function THTTPSendEx.POST(sURL, sParams: string; const sResponseStream: TStream): Boolean;
begin
  Document.Clear;
  WriteStr2Stream(sParams);
  Result := HTTPMethodPOST(sURL);
  sResponseStream.CopyFrom(Document, 0);
end;

function THTTPSendEx.POST(sURL: string; sParams: TStream;
  out sResponseStr: string): Boolean;
var
  ss: TStringStream;
begin
  Document.Clear;
  Document.LoadFromStream(sParams);
  Result := HTTPMethodPOST(sURL);
{$IFDEF DELPHI2009_UP}
  ss := TStringStream.Create;
{$ELSE}
  ss := TStringStream.Create('');
{$ENDIF}
  try

{$IFDEF DELPHI2009_UP}
    ss.LoadFromStream(Document);
{$ELSE}
    ss.CopyFrom(Document, 0);
{$ENDIF}
    sResponseStr := ss.DataString;

  finally
    FreeAndNil(ss);
  end;
end;

function THTTPSendEx.POST(sURL: string; sParams: TStream;
  const sResponseStream: TStream): Boolean;
begin
  Document.Clear;
  Document.LoadFromStream(sParams);
  Result := HTTPMethodPOST(sURL);
  sResponseStream.CopyFrom(Document, 0);
end;

function THTTPSendEx.POST(sURL: string): Boolean;
begin
  Result := HTTPMethodPOST(sURL);
end;

procedure THTTPSendEx.SetBasicAuth(const AUser, APassword: string);
begin
  if AUser<>'' then
    FBasicAuth := BASIC_AUTH_PREFIX + EncodeBase64(UTF8Encode(AUser + ':' + APassword))
  else
    FBasicAuth := '';
end;

procedure THTTPSendEx.SetBasicAuthorization;
var
  I: Integer;
begin
  for I := Headers.Count-1 downto 0 do
    if Pos(BASIC_AUTH_PREFIX, Headers[I]) = 1 then
      Headers.Delete(I);
  if FBasicAuth <> '' then
    Headers.Add(FBasicAuth);
end;

procedure THTTPSendEx.SetWork(aWorkCountMax, aWorkCount, aWorkSpeed, aWorkTimeLeft: Int64;
  const IAmWriting: Boolean);
begin
  if Assigned(fOnWork) then
  begin
    fOnWork(Self, aWorkCountMax, aWorkCount, aWorkSpeed, aWorkTimeLeft, IAmWriting);
  end;
end;

procedure THTTPSendEx.SetWorkBegin(aWorkCountMax: Int64; const IAmWriting: Boolean);
begin
  if Assigned(fOnWorkBegin) then
  begin
    fOnWorkBegin(Self, aWorkCountMax, IAmWriting);
  end;
end;

procedure THTTPSendEx.SetWorkEnd;
begin
  if Assigned(fOnWorkEnd) then
  begin
    fOnWorkEnd(Self);
  end;
end;

function THTTPSendEx.URLIsAlive(const aURL: string): Boolean;
begin
  Result := (HEAD(aURL) and IsSuccessfull);
end;

function THTTPSendEx.POST(sURL: string; sParams: TStrings;
  out sResponseStr: string): Boolean;
var
  ss: TStringStream;
var
  s: string;
begin
  s := PreprocessStrings(sParams);
  Document.Clear;
  WriteStr2Stream(s);
  Result := HTTPMethodPOST(sURL);
{$IFDEF DELPHI2009_UP}
  ss := TStringStream.Create;
{$ELSE}
  ss := TStringStream.Create('');
{$ENDIF}
  try

{$IFDEF DELPHI2009_UP}
    ss.LoadFromStream(Document);
{$ELSE}
    ss.CopyFrom(Document, 0);
{$ENDIF}
    sResponseStr := ss.DataString;

  finally
    FreeAndNil(ss);
  end;
end;

function THTTPSendEx.POST(sURL: string; sParams: TStrings;
  const sResponseStream: TStream): Boolean;
var
  s: string;
begin
  s := PreprocessStrings(sParams);
  Document.Clear;
  WriteStr2Stream(s);
  Result := HTTPMethodPOST(sURL);
  sResponseStream.CopyFrom(Document, 0);
end;

function THTTPSendEx.POST(sURL: string; sData: TMultipartFormDataStream;
  out sResponseStr: string): Boolean;
var
  ss: TStringStream;
begin
  sData.DataEnd;
  Document.Clear;
  Document.LoadFromStream(sData.Stream);
  MIMEType := sData.MIMEType;
  Result := HTTPMethodPOST(sURL);
{$IFDEF DELPHI2009_UP}
  ss := TStringStream.Create;
{$ELSE}
  ss := TStringStream.Create('');
{$ENDIF}
  try
{$IFDEF DELPHI2009_UP}
    ss.LoadFromStream(Document);
{$ELSE}
    ss.CopyFrom(Document, 0);
{$ENDIF}
    sResponseStr := ss.DataString;
  finally
    FreeAndNil(ss);
  end;
end;

function THTTPSendEx.POST(sURL: string; sData: TMultipartFormDataStream;
  const sResponseStream: TStream): Boolean;
begin
  sData.DataEnd;
  Document.Clear;
  Document.LoadFromStream(sData.Stream);
  MIMEType := sData.MIMEType;
  Result := HTTPMethodPOST(sURL);
  sResponseStream.CopyFrom(Document, 0);
end;

function THTTPSendEx.POSTWithResponce(sURL: string; out sResponseStr: string): Boolean;
var
  ss: TStringStream;
begin
  Result := HTTPMethodPOST(sURL);
{$IFDEF DELPHI2009_UP}
  ss := TStringStream.Create;
{$ELSE}
  ss := TStringStream.Create('');
{$ENDIF}
  try
{$IFDEF DELPHI2009_UP}
    ss.LoadFromStream(Document);
{$ELSE}
    ss.CopyFrom(Document, 0);
{$ENDIF}
    sResponseStr := ss.DataString;
  finally
    FreeAndNil(ss);
  end;
end;


function THTTPSendEx.PUT(sURL: string; aStream: TStream;
  out sResponseStr: string): Boolean;
var
  ss: TStringStream;
begin
  Document.Clear;
  Document.LoadFromStream(aStream);
  Result := HTTPMethodPOST(sURL, 'PUT');
{$IFDEF DELPHI2009_UP}
  ss := TStringStream.Create;
{$ELSE}
  ss := TStringStream.Create('');
{$ENDIF}
  try

{$IFDEF DELPHI2009_UP}
    ss.LoadFromStream(Document);
{$ELSE}
    ss.CopyFrom(Document, 0);
{$ENDIF}
    sResponseStr := ss.DataString;

  finally
    FreeAndNil(ss);
  end;
end;

{ TMultiPartDataStream }

procedure TMultipartFormDataStream.AddFieldBool(aFieldName: string; aValue: Boolean;
  const cUseBoolStrs: Boolean = False);
begin
  AddFieldString(aFieldName, BoolToStr(aValue, cUseBoolStrs));
end;

procedure TMultipartFormDataStream.AddFieldFloat(aFieldName: string; aValue: Extended);
begin
  AddFieldString(aFieldName, FloatToStr(aValue));
end;

procedure TMultipartFormDataStream.AddFieldInteger(aFieldName: string; aValue: Integer);
begin
  AddFieldString(aFieldName,
{$IFDEF DELPHIXE2_UP}UIntToStr(aValue){$ELSE}IntToStr(aValue){$ENDIF});
end;

procedure TMultipartFormDataStream.AddFieldString(aFieldName, aValue: string);
begin
  fStream.WriteString(#10'content-disposition: form-data; name="' + aFieldName + '"'#10);
  fStream.WriteString('Content-Type: Application/octet-string'#10);
  fStream.WriteString(''#10);
  fStream.WriteString(aValue + #10);
  fStream.WriteString(fBoundStr);
end;

procedure TMultipartFormDataStream.AddFile(aFieldName, aFileName: string; aFileContent: TStream);
begin
  fStream.WriteString(#10'content-disposition: form-data; name="' + aFieldName +
    '"; Filename="' + aFileName + '"'#10);
  fStream.WriteString('Content-Type: ' + GetFileMIMEType(aFileName) + #10);
  fStream.WriteString(''#10);
  fStream.CopyFrom(aFileContent, 0);
  fStream.WriteString(#10 + fBoundStr);
end;

procedure TMultipartFormDataStream.AddFile(aFieldName, aFile: string);
var
  MS: TMemoryStream;
begin
  fStream.WriteString(#10'content-disposition: form-data; name="' + aFieldName +
    '"; Filename="' + ExtractFileName(aFile) + '"'#10);
  fStream.WriteString('Content-Type: ' + GetFileMIMEType(aFile) + #10);
  fStream.WriteString(''#10);
  MS := TMemoryStream.Create;
  try
    MS.LoadFromFile(aFile);
    fStream.CopyFrom(MS, 0);
  finally
    FreeAndNil(MS);
  end;
  fStream.WriteString(#10 + fBoundStr);
end;

constructor TMultipartFormDataStream.Create;
begin
{$IFDEF DELPHI2009_UP}
  fStream := TStringStream.Create;
{$ELSE}
  fStream := TStringStream.Create('');
{$ENDIF}
  fBound := IntToHex(StrToInt64(FormatDateTime('ddmmyyyyhhmmssszzz', Now)), 8);
  fBoundStr := '--' + fBound;
  fStream.WriteString(fBoundStr);
  fClosed := False;
end;

procedure TMultipartFormDataStream.DataEnd;
begin
  fStream.WriteString('--'#10);
  fClosed := True;
end;

destructor TMultipartFormDataStream.Destroy;
begin
  FreeAndNil(fStream);
  inherited;
end;

function TMultipartFormDataStream.GetFileMIMEType(const aFile: string): string;
begin
  Result := clHTTPSendEx.GetFileMIMEType(aFile);
end;

function TMultipartFormDataStream.GetMimeProp: string;
begin
  Result := 'multipart/form-data; boundary=' + fBound;
end;

procedure THTTPSendEx.HookMonitor(Sender: TObject; Writing: Boolean;
  const Buffer: TMemory; Len: Integer);
var
  s, d: Ansistring;
begin
  setlength(s, len);
  move(Buffer^, pointer(s)^, len);
  if writing then
    d := '-> '
  else
    d := '<- ';
  s :=inttohex(Integer(Sender), 8) + d + s;
  FLogger.Debug(s);
end;

procedure THTTPSendEx.HookStatus(Sender: TObject;
  Reason: THookSocketReason; const Value: string);
var
  s: string;
begin
  HTTPOnStatus(Sender, Reason, Value);
  case Reason of
    HR_ResolvingBegin:
      s := 'HR_ResolvingBegin';
    HR_ResolvingEnd:
      s := 'HR_ResolvingEnd';
    HR_SocketCreate:
      s := 'HR_SocketCreate';
    HR_SocketClose:
      s := 'HR_SocketClose';
    HR_Bind:
      s := 'HR_Bind';
    HR_Connect:
      s := 'HR_Connect';
    HR_CanRead:
      s := 'HR_CanRead';
    HR_CanWrite:
      s := 'HR_CanWrite';
    HR_Listen:
      s := 'HR_Listen';
    HR_Accept:
      s := 'HR_Accept';
    HR_ReadCount:
      s := 'HR_ReadCount';
    HR_WriteCount:
      s := 'HR_WriteCount';
    HR_Wait:
      s := 'HR_Wait';
    HR_Error:
      s := 'HR_Error';
  else
    s := '-unknown-';
  end;
  s := inttohex(Integer(Sender), 8) + s + ': ' + value;
  FLogger.Debug(s);
end;

initialization
  TRegisteredFiles.Add(HInstance, GetBaseDir + FOLDER_SYSTEM + PathDelim + 'libeay32.dll', rftDll);
  TRegisteredFiles.Add(HInstance, GetBaseDir + FOLDER_SYSTEM + PathDelim + 'ssleay32.dll', rftDll);
  TRegisteredFiles.Add(HInstance, GetBaseDir + FOLDER_SYSTEM + PathDelim + 'Msvcr71.dll', rftDll);
finalization
  TRegisteredFiles.Delete(HInstance);
  if Assigned(MIMETypeCache) then
    try
      MIMETypeCache.Free;
    finally
      MIMETypeCache := nil;
    end;

end.
