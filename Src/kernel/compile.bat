;;begin :
d:\soft\masm32\bin\ml.exe /c /coff scanner.asm
d:\soft\masm32\bin\link.exe /SUBSYSTEM:WINDOWS /SECTION:.text,ERW /DLL /DEF:scanner.def scanner.obj
pause
goto begin


