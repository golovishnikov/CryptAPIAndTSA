object frmMain: TfrmMain
  Left = 192
  Top = 106
  Width = 435
  Height = 397
  Caption = 'GOST 3411 '
  Color = clBtnFace
  Constraints.MinHeight = 350
  Constraints.MinWidth = 430
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 16
    Top = 59
    Width = 47
    Height = 13
    Caption = 'Certificate'
  end
  object cbDeattached: TCheckBox
    Left = 16
    Top = 8
    Width = 217
    Height = 17
    Caption = 'Deattached '
    Checked = True
    State = cbChecked
    TabOrder = 0
  end
  object cbTSA: TCheckBox
    Left = 16
    Top = 32
    Width = 97
    Height = 17
    Caption = 'Include TSA'
    Checked = True
    State = cbChecked
    TabOrder = 1
  end
  object edTSAUrl: TEdit
    Left = 128
    Top = 29
    Width = 289
    Height = 21
    TabOrder = 2
    Text = 'http://www.cryptopro.ru/tsp/tsp.srf'
  end
  object btSign: TButton
    Left = 16
    Top = 96
    Width = 75
    Height = 25
    Caption = 'Sign'
    TabOrder = 3
    OnClick = btSignClick
  end
  object mLog: TMemo
    Left = 0
    Top = 152
    Width = 427
    Height = 218
    Align = alBottom
    Anchors = [akLeft, akTop, akRight, akBottom]
    TabOrder = 4
  end
  object edCert: TEdit
    Left = 128
    Top = 56
    Width = 265
    Height = 21
    ReadOnly = True
    TabOrder = 5
  end
  object btSelectCert: TButton
    Left = 395
    Top = 54
    Width = 24
    Height = 25
    Caption = '...'
    TabOrder = 6
    OnClick = btSelectCertClick
  end
  object OpenDialog: TOpenDialog
    Title = 'Select a file for the signature'
    Left = 336
    Top = 56
  end
end
