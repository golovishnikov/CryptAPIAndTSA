unit MISGZIPUtil;

interface

uses
  Classes, AbZipper, AbUnzper, AbUtils;

procedure GZDecompressStream(ASrc, ADest: TStream);
procedure GZCompressStream(ASrc, ADest: TStream);

implementation

procedure GZDecompressStream(ASrc, ADest: TStream);
var
  Zip: TAbUnZipper;
begin
  Zip := TAbUnZipper.Create(nil);
  try
    Zip.ArchiveType := atGzip;
    Zip.ForceType := True;
    Zip.Stream := ASrc;
    ASrc.Position := 0;
    Zip.ExtractToStream('', ADest);
  finally
    Zip.Free;
  end;
end;

procedure GZCompressStream(ASrc, ADest: TStream);
var
  Zip: TAbZipper;
begin
  Zip := TAbZipper.Create(nil);
  try
    Zip.ArchiveType := atGzip;
    Zip.ForceType := True;
    Zip.Stream := ADest;
    ASrc.Position := 0; 
    Zip.AddFromStream('', ASrc);
  finally
    Zip.Free;
  end;
end;

end.
