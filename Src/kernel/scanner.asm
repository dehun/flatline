;***************************************************************;
;	Kernel.dll - contain main functions			;
;***************************************************************;
;	Author	:	Netesoff Yurii aka DeHunter		;
;	EMail	:	dehunter@inbox.ru			;
;	ICQ	:	422259					;
;	Site	:	dehunters_soft.drmist.ru		;
;***************************************************************; 

title scanner_dll	
option casemap:none	
.386
.model flat, stdcall
;===================== some inc =========================;
include 	d:/soft/masm32/include/windows.inc
include 	d:/soft/masm32/include/user32.inc
include 	d:/soft/masm32/include/kernel32.inc
includelib	d:/soft/masm32/lib/kernel32.lib
includelib	d:/soft/masm32/lib/user32.lib
;======================= EXPORTS =========================;
public hCurScanEdt
public hMPB
public hRepFile
public pSet
public DeleteAction
public CureAction
public MoveToQAction
public hEmulTrd
;======================= TYPEDEF =========================;
SEH struct
	PrevLink	DD	 ?    ; the address of the previous seh structure
	CurHandler	DD	 ?    ; the address of the exception handler
	SafeOffset	DD	 ?    ; The offset where it's safe to continue execution
	PrevESP		DD	 ?    ; the old value in esp
	PrevEBP		DD	 ?    ; The old value in ebp
SEH ends

;======================= PROTO ===========================;
AFADlgProc	PROTO	hDlg : DWORD, uMsg : DWORD, wParam : DWORD, lParam : DWORD
EmulateCmd	PROTO	pinst : DWORD
;======================= CONSTANTS ======================;
	BUFF_SIZE		equ	256
	CRCPOLY			equ	0EDB88320H
	ext			equ	offset ext1
	EMULATOR_TIME_LIMIT	equ	32			; time in seconds
	EMUL_STACK_SIZE		equ	10000H			; size in bytes
	CHECK_AFTER_N_CMDS	equ	16			; after what cmd(num) check file for virz
;======================= GLOBAL DATA ====================;
.DATA?
;---------- emualtor varz
	OldData			DB	16 dup(?)
	nOldDataSize		DB	?
	hEmulTrd		DD	?
	addr_of_sections_heads	DD	?
	need_av_check		DB	?
	last_addr		DD	?
	need_check		DD	?
	are_3_ops		DB	?
	pRealPE			DD	?
	number_of_sections	DD	?
	prefixfl		DW	?	; 67H, 66H, 65H, 64H, 26H, 3EH, 36H, 2EH, F3H, F2H, F0H
	cur_eip			DD	?
	main_opcode		DB	?
	modrmb			DB	?
	regz			DD	8 dup(?)
	flagz			DD	?
	pstack			DD	?
	pProbPacked		DD	?
	inh			IMAGE_NT_HEADERS	<?>
;---------- other varz  
	filename_t		DD	?
	virname_t		DD	?
	tBuffSize		DD	?
	hfMapVdb		DD	?
	hfVdb			DD	?
	fSize			DD	?	
	DlgParam		DQ	?
	RetRez			DB	?
	hCureLib		DD	?
	pSet			DD	?
	hTimet			DD	?
	fCounter		DD	?
	hRepFile		DD	?
	nmExtCounter		DD	?
	ScanLevel		DB	?
	pVDB			DD	?
	VDBCounter		DD	?
	buffer			DB	BUFF_SIZE dup(?) 
	rw			DD	?
	crc_table		DD	256 dup(?)
	nInfCount		DD	?
	pExt			DD	?
	wfd    			WIN32_FIND_DATA	<?>
	hCurScanEdt		DD	?
	hMPB			DD	?
	hMapFile 		DD	?
	hFile			DD	?
	pFileBuff 		DD	?
	ProbPacked		DD	?
.DATA
	;------- table of addr of action functions
	ActionsTable		DD	DeleteAction
				DD	CureAction
				DD	MoveToQAction
				DD	AskForAction
	;------- other shit
	SigLibStr		DB	"SigLib.vdb", 0
	CureDllStr		DB	"Cure.dll", 0
	pProbPackStr		DB	"ProbPacked", 0
	VDBVarStr		DB	"pVDBVar", 0
	ext1			DB	"*.*", 0
	LastRepStr		DB	"last.rep", 0
	                	
	HealthyStr		DB	"healthy", 23 dup(0) 
	failurestr		DB	"failure", 23 dup(0)
	SkipedStr		DB	"skiped", 24 dup(0)
	                	
	MainTitleStr		DB	"FlatLine scanner 0x1", 0
	DeleteActionFuckStr 	DB	"Can't delete file : ", 0
	CantCopyToQStr		DB	"Can't copy to quarantine file : ", 0
	                	
	PrepareToScan		DB	"Prepare to scan...", 0
;========================================================;

;======================== CODE ==========================;
.CODE
;################################################ ACTIONS ##############################################;
;=======================================================================;
;	Name	: DeleteAction						;
;	Proto	: DeleteAction(char *filename, char *virname)		;
;	Descr.	: Action	 					;
;	Ret	: 0 - succ, 1 - fuck					;
;=======================================================================;
DeleteAction	PROC	filename : DWORD, virname : DWORD
	invoke UnmapViewOfFile, pFileBuff
	invoke CloseHandle, hMapFile
	invoke CloseHandle, hFile
	invoke DeleteFile, filename
	test eax, eax
	jz DeleteAction_fuck
	xor eax, eax
	ret
DeleteAction_fuck :
	invoke lstrcpy, offset buffer, offset DeleteActionFuckStr
	invoke lstrcat, offset buffer, filename
	invoke MessageBoxA, 0, offset buffer, offset MainTitleStr, 0
	xor eax, eax
	inc eax
	ret
DeleteAction	ENDP
	
;=======================================================================;
;	Name	: CureAction						;
;	Proto	: CureAction(char *filename, char *virname)		;
;	Descr.	: Action	 					;
;	Ret	: 0 - succ, !0 - fuck					;
;=======================================================================;
CureAction	PROC
;------- are library loaded ?
	mov fCounter, 2
	cmp hCureLib, 0
	jz if_cant_cure
;------- Yeah! It was Loaded ! Try to cure fucked virus		
	invoke GetProcAddress, hCureLib, virname_t
	test eax, eax
	jz CureAction_failure
		mov edx, pProbPacked
		mov ebx, ProbPacked
		mov dword ptr [edx], ebx
		push filename_t
		call eax
		test eax, eax
		jz cure_action_finish
CureAction_failure :
	mov edx, pSet
	mov al, byte ptr [edx+514]
	jmp if_cant_cure
CureAction	ENDP

;=======================================================================;
;	Name	: MoveToQAction						;
;	Proto	: MoveToQAction(char *filename, char *virname)		;
;	Descr.	: Action	 					;
;	Ret	: 0 - succ, !0 - fuck					;
;=======================================================================;
MoveToQAction	PROC	filename : DWORD, virname : DWORD
	invoke lstrcpy, offset buffer, pSet 
	invoke lstrlen, filename
	mov ecx, eax
	add eax, filename
	xchg eax, edi
	mov al, 05CH
	std
	repne scasb
	cld
	add edi, 2
	invoke lstrcat, offset buffer, edi
	invoke MoveFile, filename, offset buffer
	test eax, eax
	jz MoveToQAction_Err
	xor eax, eax
	ret
MoveToQAction_Err :
	dec eax
	ret
MoveToQAction	ENDP

;=======================================================================;
;	Name	: AskForAction						;
;	Proto	: AskForAction(char *filename, char *virname)		;
;	Descr.	: Action	 					;
;	Ret	: 0 - succ, !0 - fuck					;
;=======================================================================;
AskForAction	PROC
	invoke GetModuleHandle, 0
	pop dword ptr DlgParam[0]
	pop dword ptr DlgParam[4]
	invoke DialogBoxParam, eax, 301,  0, offset AFADlgProc, offset DlgParam
	mov al, RetRez
	jmp if_cant_cure
AskForAction	ENDP

;=======================================================================;
;	Name	: ADADlgProc						;
;	Proto	: AFADlgProc(HWND hWnd, UINT uMsg, WPARAM wparam, ...)	;
;	Descr.	: Dialog proc for AF Action	 			;
;	Ret	: 1 or 0						;
;=======================================================================;
AFADlgProc	PROC	hDlg : DWORD, uMsg : DWORD, wParam : DWORD, lParam : DWORD
	mov eax, uMsg
	cmp eax, WM_INITDIALOG
	jnz not_wm_init_dialog
	;======== WM_INITDIALOG
		mov ebx, offset DlgParam
		invoke SetDlgItemText, hDlg, 5000, [ebx]
		add ebx, 4
		invoke SetDlgItemText, hDlg, 5005, [ebx]
		xor eax, eax
		inc eax
		ret
		
	;=========================
not_wm_init_dialog :
	cmp eax, WM_COMMAND
	jnz not_wm_command
	;========== WM_COMMAND
		mov eax, wParam
		cmp ax, 5001
		jnz not_deleteit_btn
		;------- delete btn
			mov RetRez, 1
			jmp EndAFADlg
		;------------------
	not_deleteit_btn :
		cmp ax, 5002
		jnz not_cure_btn
		;-------- cure btn
			mov RetRez, 2
			jmp EndAFADlg
		;-----------------
	not_cure_btn :
		cmp ax, 5003
		jnz not_movetoq_btn
		;-------- mov to Q btn
			mov RetRez, 3
			jmp EndAFADlg
		;---------------------
		not_movetoq_btn :
		cmp ax, 5004
		jnz not_donothing_btn
		;-------- do nothing btn
			mov RetRez, 0
			jmp EndAFADlg
		;-----------------------
	not_donothing_btn :
		xor eax, eax
		inc eax
		ret
	;================================
	;========== DEFAULT
not_wm_command :
default :
	xor eax, eax
	ret
EndAFADlg :
	invoke EndDialog, hDlg, 0
	xor eax, eax
	inc eax
	ret
AFADlgProc	ENDP

;################################### SCAN PROCEDUREZZZ ####################################;
;=======================================================================;
;	Name	: GetRealAddress					;
;	Proto	: GetRealAddress( DWORD vaddr ) 			;
;	Descr.	: return real addr in mem				;
;	Ret	: -1 - fuck, rl addr - succ				;
;=======================================================================;
GetRealAddress	PROC	vaddr : DWORD				; it cmp with old ImageBase
	pushad
	mov ebx, vaddr
	mov last_addr, ebx
	mov eax, inh.OptionalHeader.ImageBase
	cmp ebx, eax
	jb bad_addr
	add eax, inh.OptionalHeader.SizeOfImage
	cmp ebx, eax
	ja bad_addr
	sub ebx, inh.OptionalHeader.ImageBase
	add ebx, pRealPE
	mov vaddr, ebx
	popad
	push eax
	mov ebx, vaddr
	mov eax, [ebx]
	mov dword ptr OldData[0], eax
	mov nOldDataSize, 4
	mov need_av_check, 1
	pop eax
	ret
bad_addr :
	popad
	xor ebx, ebx
	dec ebx
	ret
GetRealAddress	ENDP

;=======================================================================;
;	Name	: CheckSig						;
;	Proto	: CheckSig(byte *pMapBuff)				;
;	Descr.	: check for virus signatures 				;
;	Ret	: 0 - clear, -1 - failure, [1;-2] - pointer to name	;
;=======================================================================;
CheckSig	PROC	pMapBuff:DWORD, FType : BYTE, BuffSize:DWORD
	xor eax, eax
	mov esi, pMapBuff
	mov edi, pVDB
	add edi, 4
	mov ecx, BuffSize
	sub ecx, 4
	jbe end_search
;------------------- main loop		
chk_mlp :
	mov ax, word ptr [esi]
	inc esi
	push ecx
	push edi
	push esi
	mov ecx, dword ptr [edi+eax*8]
	test ecx, ecx
	jz next_byte
	mov ebx, dword ptr [edi+eax*8+4]
	add ebx, edi
	sub ebx, 4
	movzx edx, byte ptr [ebx+51]
	sub edx, 2
	mov edi, ebx
	inc esi
	add edi, 54
	;---------- sub loop
	chk_sublp :
		push esi
		cmp [esp+12], edx
		jb next_sig
	chk_sublp_cmp :
		mov al, byte ptr [edi]
		cmp al, '?'
		jz next_sig_byte
		cmp al, '*'
		jz spec_byte
		cmp al, byte ptr [esi]
		jnz next_sig
	next_sig_byte :
		inc edi
		inc esi
		dec edx
		jnz chk_sublp_cmp
		;--------- if it is virus
		pop eax
		pop eax
		pop eax
		pop eax
		xchg eax, ebx
		ret
next_sig :
	pop esi
;------ are last sing ?
	dec ecx
	jz next_byte
;------- if no
	movzx eax, byte ptr [ebx+51]
	add ebx, eax				; can change to lea ( AHTUNG )
	add ebx, 52
	mov edi, ebx
	add edi, 54
	movzx edx, byte ptr [ebx+51]
	sub edx, 2
	jmp chk_sublp
;----------- next word
next_byte :
	pop esi
	pop edi
	pop ecx
	dec ecx
	jnz chk_mlp
;------------- if there is no virus
end_search :
	xor eax, eax
	ret	
;------------- if '*'
spec_byte :
	push edx
	sub edx, BuffSize
	neg edx
	inc edi
spec_byte_loop :
	cmp esi, edx
	ja end_spec_byte_failure
	inc edi
	mov al, byte ptr [edi]
	_spec_byte_lp :
		cmp esi, edx
		ja end_spec_byte_failure
		mov al, byte ptr [esi]
		inc esi
		cmp al, byte ptr [edi]
		jnz _spec_byte_lp
;---------- if we found next byte
end_spec_byte_success :
	pop edx
	inc edi
	jmp chk_sublp_cmp
;---------- if we didn't found next byte
end_spec_byte_failure :
	pop edx
	jmp next_sig
CheckSig	ENDP

;=======================================================================;
;	Name	: AreAcVio						;
;	Proto	: AreAcVio( DWORD dwRWE, pNewData )			;
;	Descr.	: Check for access violation				;
;	Ret	: !0 - acc vio, 0 - all right				;
;=======================================================================;
AreAcVio	PROC	dwRWE : DWORD, pNewData : dword
		;------ get page characteristics
		mov ebx, pNewData
		mov esi, addr_of_sections_heads
		ASSUME esi : ptr IMAGE_SECTION_HEADER
		movzx ecx, word ptr inh.FileHeader.NumberOfSections
	acc_vio_chk_what_section_loop :
			mov eax, [esi].VirtualAddress
			add eax, inh.OptionalHeader.ImageBase
			cmp ebx, eax
			jb acc_vio_chk_next_section_cmp
				add eax, [esi].Misc
				cmp ebx, eax
				jae acc_vio_chk_next_section_cmp
					mov edx, [esi].Characteristics
					jmp acc_vio_chk_section_found
		acc_vio_chk_next_section_cmp :
			add esi, sizeof IMAGE_SECTION_HEADER
			loop acc_vio_chk_what_section_loop
	;---------- if section dosn't found ( it is zero section ( pe header ) or stack) 
		mov eax, pstack
		cmp ebx, eax
		jb acc_vio_not_stack
			add eax, EMUL_STACK_SIZE
			cmp ebx, eax
			ja acc_vio_not_stack
			mov edx, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
			jmp acc_vio_chk_section_found
	acc_vio_not_stack :
		mov edx, IMAGE_SCN_MEM_READ
		jmp acc_vio_chk_section_found
	;---------- if section found
	acc_vio_chk_section_found :
		test edx, dwRWE
		jz AreAcVio_Access_Violation
			xor eax, eax
			ret
	AreAcVio_Access_Violation :
		mov al, 1
		ret
AreAcVio	ENDP
;=======================================================================;
;	Name	: EmulateTrd						;
;	Proto	: EmulateTrd(byte *)					;
;	Descr.	: emulate thread 					;
;	Ret	: -1 err, 0 - healthy, other - pointer to virname	;
;=======================================================================;
EmulateTrd	PROC	filename: DWORD
LOCAL	seh : SEH
;------ set prioritity
	invoke GetCurrentThread
	invoke SetThreadPriority, eax, THREAD_PRIORITY_ABOVE_NORMAL
;------ create seh frame for this thread
	ASSUME fs : nothing
	push fs:[0]
	pop seh.PrevLink
	mov seh.CurHandler, offset EmulatorTrd_ExceptionHandler
	mov seh.SafeOffset, offset EmulatorTrd_TotalError
	lea eax, seh
	mov fs:[0], eax
	mov seh.PrevESP, esp
	mov seh.PrevEBP, ebp
;------ init regz with the mess
	;----- gpr init
	xor eax, eax
	mov flagz, eax
	mov prefixfl, ax
	mov regz[00], eax
	mov regz[04], 0012FFB0H
	mov regz[08], 7C90EB94H
	mov regz[12], 7FFDE000H
	push pstack
	pop regz[16]
	add regz[16], EMUL_STACK_SIZE-1
	mov regz[20], 0012FF00H
	mov regz[24], 0FFFFFFFFH
	mov regz[28], 7C910738H
;------- load file into memory
	;------- load image_nt_headers
	mov esi, pFileBuff
	mov ebx, dword ptr [esi+3CH]
	cld
	mov ecx, sizeof IMAGE_NT_HEADERS
	mov edi, offset inh
	add esi, ebx
	rep movsb
	push inh.OptionalHeader.AddressOfEntryPoint
	pop cur_eip
	;-------- alloc mem
	invoke VirtualAlloc, 0, inh.OptionalHeader.SizeOfImage, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE
	test eax, eax
	jz EmulatorTrd_TotalError
	;-------- zero mem
	mov pRealPE, eax
	xchg edi, eax
	xor eax, eax
	mov ecx, inh.OptionalHeader.SizeOfImage
	rep stosb
	;-------- load zero section ( dos header, pe header, sections headers)
	add ebx, sizeof IMAGE_NT_HEADERS
	movzx eax, inh.FileHeader.NumberOfSections
	imul eax, eax, sizeof IMAGE_SECTION_HEADER
	mov ecx, ebx
	add ecx, eax
	mov edx, ecx
	mov edi, pRealPE
	mov esi, pFileBuff
	rep movsb
	mov eax, ebx
	add ebx, pRealPE
	mov addr_of_sections_heads, ebx
	;-------- build sections
	ASSUME eax : ptr IMAGE_SECTION_HEADER
	add eax, pFileBuff
	push eax
	push edx
		;------- load info from image_nt_headers to first section
		;----- try to find nearest section
		mov edx, fSize
		movzx ecx, word ptr inh.FileHeader.NumberOfSections
	fns_loop :
		mov ebx, [eax].PointerToRawData
		test ebx, ebx
		jz next_fns_steep
		cmp edx, ebx
		jb next_fns_steep
			mov edx, ebx
	next_fns_steep :
			add eax, sizeof IMAGE_SECTION_HEADER
			loop fns_loop
		cmp edx, fSize
		jz EmulatorTrd_TotalError
		sub eax, sizeof IMAGE_SECTION_HEADER
		sub eax, pFileBuff
		;---------------------------------
			mov ecx, edx
			pop edx
			sub ecx, eax
			rep movsb
		;----------------------------------------------------
	pop eax
	mov ebx, edx
	mov ecx, inh.OptionalHeader.FileAlignment
	dec ecx
	add ebx, ecx
	not ecx
	and ebx, ecx
	;--------- load some data which is during pe header and first section va
	xor edx, edx
build_sections_loop :
		mov edi, [eax].VirtualAddress
		mov esi, [eax].PointerToRawData
		add esi, pFileBuff
		mov ecx, [eax].Misc
		add ecx, edi
		cmp ecx, inh.OptionalHeader.SizeOfImage
		ja EmulatorTrd_TotalError
		cmp edi, ebx
		jb EmulatorTrd_TotalError
		mov ecx, [eax].SizeOfRawData
		add edi, pRealPE
		rep movsb
		add eax, sizeof IMAGE_SECTION_HEADER
		inc edx
		cmp dx, inh.FileHeader.NumberOfSections
		jne build_sections_loop
	;----- close previus file
	invoke UnmapViewOfFile, pFileBuff
	invoke CloseHandle, hMapFile
	invoke CloseHandle, hFile
	ASSUME eax : NOTHING
;------------- do first check. Prob we will not need check in future
	mov ProbPacked, 0
	;invoke CheckSig, pRealPE, 1, inh.OptionalHeader.SizeOfImage
	;test eax, eax
	;jnz EmulatorTrd_VirusFound
	;mov ProbPacked, 1
;------------- calculate real entry point
	mov eax, inh.OptionalHeader.ImageBase
	add cur_eip, eax
	invoke GetRealAddress, cur_eip
	inc ebx
	jz EmulatorTrd_TotalError
	dec ebx
	mov cur_eip, ebx
	;------- main emulator loop
	;int 3h		; AHTUNG ! DEBUG !
	main_emulator_loop :
		;------ check esp
		mov eax, regz[16]
		mov ebx, pstack
		cmp eax, ebx
		jb EmulatorTrd_stack_overflow
		add ebx, EMUL_STACK_SIZE
		cmp eax, ebx
		ja EmulatorTrd_stack_overflow
		;----- emul cmd
		invoke EmulateCmd, cur_eip
		inc eax
		jz EmulatorTrd_TotalError
		cmp need_av_check, 1
		jmp not_need_av_check;jnz not_need_av_check			; AHTUNG
			mov esi, last_addr
			mov edi, offset OldData
			movzx ecx, byte ptr nOldDataSize
			repe cmpsb
			jnz av_check_was_writing
			;----- check for reading
			invoke AreAcVio, IMAGE_SCN_MEM_READ, last_addr
			test eax, eax
			jnz EmulatorTrd_AccessViolation
			jmp not_need_av_check
			;----- check for writing
		av_check_was_writing :
			invoke AreAcVio, IMAGE_SCN_MEM_WRITE, last_addr
			test eax, eax
			jnz EmulatorTrd_AccessViolation
	not_need_av_check :
		;===================== check for virusez
		dec need_check 
		jnz not_need_check
			invoke CheckSig, pRealPE, 1, inh.OptionalHeader.SizeOfImage
			test eax, eax
			jnz EmulatorTrd_VirusFound
			mov edx, pSet
			add edx, 256 + 256 + 4
			mov eax, [edx]
			mov need_check, eax
	not_need_check :
		;----- check cur_eip
		mov eax, cur_eip
		cmp eax, pRealPE
		jb EmulatorTrd_End
		mov ebx, pRealPE
		add ebx, inh.OptionalHeader.SizeOfImage
		cmp eax, ebx
		ja EmulatorTrd_End
		mov eax, cur_eip
		sub eax, pRealPE
		add eax, inh.OptionalHeader.ImageBase
		invoke AreAcVio, IMAGE_SCN_MEM_EXECUTE, eax
		test eax, eax
		jmp main_emulator_loop
;------------ if Stack overflow or simply time limit was hited
EmulatorTrd_End :
EmulatorTrd_stack_overflow :
EmulatorTrd_AccessViolation :
	cmp need_check, 1
	jae test_before_exit_1
	EmulatorTrd_End_total :
		invoke VirtualFree, pRealPE, inh.OptionalHeader.SizeOfImage, MEM_DECOMMIT
		invoke ExitThread, 0
;-------- if total error
EmulatorTrd_TotalError :
	cmp need_check, 1
	jae test_before_exit_2
EmulatorTrd_TotalError_end :
	invoke VirtualFree, pRealPE, inh.OptionalHeader.SizeOfImage, MEM_DECOMMIT
	invoke ExitThread, -1	
EmulatorTrd_VirusFound :
	mov ebx, eax
	invoke VirtualFree, pRealPE, inh.OptionalHeader.SizeOfImage, MEM_DECOMMIT
	invoke ExitThread, ebx
;------- test before exit
test_before_exit_1 :
	invoke CheckSig, pRealPE, 1, inh.OptionalHeader.SizeOfImage
	test eax, eax
	jnz EmulatorTrd_VirusFound
	jmp EmulatorTrd_End_total
test_before_exit_2 :
	invoke CheckSig, pRealPE, 1, inh.OptionalHeader.SizeOfImage
	test eax, eax
	jnz EmulatorTrd_VirusFound
	jmp EmulatorTrd_TotalError_end

EmulateTrd	ENDP

;=======================================================================;
;	Name	: EmulatorTrd_ExceptionHandler				;
;	Proto	: Emulate(...)						;
;	Descr.	: seh handler for emulator trd				;
;	Ret	: nothing						;
;=======================================================================;
EmulatorTrd_ExceptionHandler	PROC	 pExcept:DWORD, pFrame:DWORD, pContext:DWORD, pDispatch:DWORD
	mov edx, pFrame
	ASSUME edx : ptr SEH
	mov eax, pContext
	ASSUME eax : ptr CONTEXT
	push [edx].SafeOffset
	pop [eax].regEip
	push [edx].PrevESP
	pop [eax].regEsp
	push [edx].PrevEBP
	pop [eax].regEbp	
	ASSUME edx : nothing
	ASSUME eax : nothing
	mov eax, ExceptionContinueExecution
	ret
EmulatorTrd_ExceptionHandler	ENDP
;=======================================================================;
;	Name	: Emulate						;
;	Proto	: Emulate(byte *buff)					;
;	Descr.	: launch emulator thread and wait for it		;
;	Ret	: 0 - clear, -1 - failure, [1;-2] - pointer to result	;
;=======================================================================;
Emulate		PROC	filename:dword
;---------- create tread
	xor ebx, ebx
	invoke CreateThread, ebx, 1000, EmulateTrd, filename, ebx, ebx
	mov hEmulTrd, eax
;----------- wait for EmulateThread
	mov edx, pSet
	add edx, 256 + 256 + 4
	invoke WaitForSingleObject, hEmulTrd, dword ptr [edx]
;------------ free al mem
	invoke VirtualFree, pRealPE, inh.OptionalHeader.SizeOfImage, MEM_DECOMMIT or MEM_RELEASE
;------------ are file healthy ?
	invoke GetExitCodeThread, hEmulTrd, offset rw
	cmp rw, -1
	jz Emulate_Error
	cmp rw, STILL_ACTIVE
	jz Emulate_Time_Limit
	cmp rw, 0
	jz Emulate_helthy
;--------------- file infected
		mov eax, rw
		ret
;--------------- file helthy or timelimit
Emulate_Error :
Emulate_Time_Limit :
	invoke VirtualFree, pRealPE, inh.OptionalHeader.SizeOfImage, MEM_DECOMMIT
	invoke TerminateThread, hEmulTrd, 0
Emulate_helthy :
	invoke VirtualFree, pRealPE, inh.OptionalHeader.SizeOfImage, MEM_DECOMMIT
	xor eax, eax
	ret

Emulate		ENDP


;=======================================================================;
;	Name	: GetFType						;
;	Proto	: GetFTYpe(byte *buff)					;
;	Descr.	: Get file type						;
;	Ret	: 0 - pe, 1- other					;
;=======================================================================;
GetFType	PROC	pbuff : dword
LOCAL	seh : SEH
;----------- setup seh
	ASSUME fs : nothing
	push fs:[0]
	pop seh.PrevLink
	mov seh.CurHandler, offset EmulatorTrd_ExceptionHandler
	mov seh.SafeOffset, offset not_pe
	lea eax, seh
	mov fs:[0], eax
	mov seh.PrevESP, esp
	mov seh.PrevEBP, ebp
;----------- check
	cmp fSize, 3FH
	jb not_pe
	mov esi, pbuff
	mov ax, word ptr [esi]
	cmp ax, 'ZM'
	jnz not_pe
	mov ax, word ptr [esi+18h]
	cmp eax, 40h
	jnae not_pe
	mov eax, dword ptr [esi+03ch]
	sub fSize, 4
	cmp eax, fSize
	ja not_pe
	add eax, esi
	mov eax, [eax]
	cmp ax,  'EP'
	jnz not_pe
;--------- if pe
	xor eax, eax
	ret
;------- not pe
not_pe :
	xor eax, eax
	inc eax
	ret
GetFType	ENDP

;=======================================================================;
;	Name	: InitCRCTable						;
;	Proto	: InitCRCTable(void)					;
;	Descr.	: Init crc table					;
;	Ret	: nothing						;
;=======================================================================;
InitCRCTable	PROC
	xor ecx, ecx
	mov esi, offset crc_table
main_crc_table_init_loop :
	movzx eax, cl
	xor ebx, ebx
	;-------------
	sub_crc_table_init_loop :
		test eax, 1
		jz crc_lb1
			shl eax, 1
			xor eax, CRCPOLY
			jmp sub_crc_table_init_loop_end
	crc_lb1 :
		shl eax, 1
sub_crc_table_init_loop_end :
		inc ebx
		cmp ebx, 8
		jne sub_crc_table_init_loop
	;-----------
	mov dword ptr [esi], eax
	add esi, 4
	inc ecx
	cmp ecx, 256
	jnz main_crc_table_init_loop
	ret
InitCRCTable	ENDP

;=======================================================================;
;	Name	: CalcCRC						;
;	Proto	: CalcCRC(char *crcbuff, BYTE crcsize)			;
;	Descr.	: Calculate checksum of buff				;
;	Ret	: checksum(dword)					;
;=======================================================================;
CalcCRC		PROC	crcbuff:dword, crcsize:byte
	xor ecx, ecx
	mov esi, crcbuff
	xor eax, eax 				; mov eax, 0FFFFFFFFH or mov eax, -1
	dec eax					; see 1 line up
main_CalcCRC_loop :
	mov ebx, eax
	xor bl, [esi]
	and ebx, 0FFH
	mov ebx, crc_table[ebx]
	shr eax, 8
	xor eax, ebx
	inc esi
	inc ecx
	cmp cl, crcsize
	jne main_CalcCRC_loop
	not eax
	ret	
CalcCRC		ENDP

;=======================================================================;
;	Name	: Check							;
;	Proto	: Check(char *filename)					;
;	Descr.	: Check [pathname] file for virusez			;
;	Ret	: Code of result, 0r -1 if error			;
;=======================================================================;
Check		PROC	filename : dword
;---------------- shiw progress
	invoke SendMessage, hCurScanEdt, WM_SETTEXT, 0, filename
;---------------- open file
	;int 3h
	invoke CreateFileA, filename, GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_DELETE, 0, OPEN_ALWAYS, \
			    FILE_ATTRIBUTE_NORMAL, 0
	mov hFile, eax
	inc eax
	jnz check_file_opened_success
		invoke WriteFile, hRepFile, filename, BUFF_SIZE, offset rw, 0
		invoke lstrcpy, offset buffer, offset failurestr
		invoke WriteFile, hRepFile, offset buffer, sizeof buffer, offset rw, 0
		mov fCounter , 0 
		invoke WriteFile, hRepFile, offset fCounter, 1, offset rw, 0
		or eax, -1
		ret
check_file_opened_success :
	invoke GetFileSize, hFile, 0
	test eax, eax
	jz skip_this_file
	mov fSize, eax
	xchg eax, ebx
	invoke CreateFileMapping, hFile, 0, PAGE_READONLY, 0, ebx, 0
	mov hMapFile, eax
	test eax, eax
	jz Error_create_mapped
		xor eax, eax
		push ebx
		invoke MapViewOfFile, hMapFile, FILE_MAP_READ, eax, eax, eax 
		mov ebx, eax
		mov pFileBuff, eax
		invoke GetFType, pFileBuff
		test eax, eax
		jnz check_not_pe
		pop eax
		mov eax, pSet
		mov al, byte ptr [eax+512]
		test al, 04H
		jz no_emulation_mode
		invoke Emulate, filename
		jmp end_of_checksig
	no_emulation_mode :
		test al, 01H
		jz healthy
		;int 3h
		invoke CheckSig, ebx, 2, fSize
	end_of_checksig :
		xchg eax, ebx
		test ebx, ebx
		jnz not_healthy
		;------- add only infected ?
			mov edx, pSet
			mov al, byte ptr [edx+515]
			test al, al
			jnz Check_correct_exit
		;------- not only infected
	healthy :
			push eax
			invoke WriteFile, hRepFile, filename, BUFF_SIZE, offset rw, 0
			invoke lstrcpy, offset buffer, offset HealthyStr
			invoke WriteFile, hRepFile, offset buffer, sizeof buffer, offset rw, 0
			mov fCounter, 0
			invoke WriteFile, hRepFile, offset fCounter, 1, offset rw, 0
			pop eax
			jmp Check_correct_exit
	not_healthy :
			;------------ unmap file
			invoke UnmapViewOfFile, pFileBuff
			invoke CloseHandle, hMapFile
			invoke CloseHandle, hFile
			;------------
			invoke WriteFile, hRepFile, filename, BUFF_SIZE, offset rw, 0
			invoke lstrcpy, offset buffer, ebx
			invoke WriteFile, hRepFile, offset buffer, sizeof buffer, offset rw, 0
			;----------------- do something with viruz
			mov edx, pSet
			mov al, byte ptr [edx+513]
			;----- copy to quarantine ?
			cmp al, 3
			jz not_copy_to_quarantine
			test al, 10000000b
			jz not_copy_to_quarantine
			;------- copy to Q
					pushad
					mov ebx, filename
					invoke lstrcpy, offset buffer, edx 
					invoke lstrlen, ebx
					mov ecx, eax
					add eax, ebx
					xchg eax, edi
					mov al, 05CH
					std
					repne scasb
					cld
					add edi, 2
					invoke lstrcat, offset buffer, edi
					invoke MoveFile, filename, offset buffer
					test eax, eax
					jnz copy_to_q_succ
						invoke lstrcpy, offset buffer, offset CantCopyToQStr
						invoke lstrcat, offset buffer, ebx
						invoke MessageBox, 0, offset buffer, offset MainTitleStr, 0
				copy_to_q_succ :
				popad
		;------------------ Continue
		not_copy_to_quarantine :
			xor eax, eax
			mov al, byte ptr [edx+513]
			and al, 01111111b
		if_cant_cure ::
			test al, al
			jz no_action
				and eax, 000000FFH
				cmp eax, 4
				jnz not_afa
				;----- afa
					push ebx
					push filename
					jmp AskForAction
				;--------
			not_afa :
				cmp eax, 2
			;-------- cur eactio
				jnz not_cure
					mov eax, filename
					mov filename_t, eax
					mov virname_t, ebx
					jmp CureAction
			not_cure :
			;-------------------
				mov fCounter, eax
			;----- action
				push ebx
				push filename
				dec eax
				shl eax, 2
				call ActionsTable[eax]
				test eax, eax
				jnz no_action
			ActionsTable_Succ :
				invoke WriteFile, hRepFile, offset fCounter, 1, offset rw, 0
				jmp Check_correct_exit
		no_action :
				mov fCounter, 0
		cure_action_finish ::
				invoke WriteFile, hRepFile, offset fCounter, 1, offset rw, 0
				jmp Check_correct_exit
	;-------- check not pe
	check_not_pe :
		invoke CheckSig, ebx, 2, fSize
		jmp end_of_checksig
	;-------- check exit
	Check_correct_exit ::
		invoke UnmapViewOfFile, pFileBuff
		invoke CloseHandle, hMapFile
		invoke CloseHandle, hFile
		xchg eax, ebx
		ret
	skip_this_file :
		mov edx, pSet
		mov al, byte ptr [edx+515]
		test al, al
		jnz Check_healthy_ret
		invoke WriteFile, hRepFile, filename, BUFF_SIZE, offset rw, 0
		invoke lstrcpy, offset buffer, offset SkipedStr
		invoke WriteFile, hRepFile, offset buffer, sizeof buffer, offset rw, 0
		mov fCounter , 0 
		invoke WriteFile, hRepFile, offset fCounter, 1, offset rw, 0
		invoke CloseHandle, hFile
		xor eax, eax
	Check_healthy_ret :
		ret
		
Error_create_mapped :
	invoke lstrcpy, offset buffer, offset failurestr
	invoke WriteFile, hRepFile, offset buffer, sizeof buffer, offset rw, 0
	mov fCounter, 0
	invoke WriteFile, hRepFile, offset fCounter, 1, offset rw, 0
	invoke CloseHandle, hFile
	or eax, -1
	ret
	
Check		ENDP

;=======================================================================;
;	Name	: Start							;
;	Proto	: Start(void)						;
;	Descr.	: load siglib at start and free it on exit		;
;	Ret	: 1							;
;=======================================================================;
Start		PROC	hMod:DWORD, fdwReason:DWORD, fImpLoad:DWORD 
	cmp fdwReason, DLL_PROCESS_ATTACH
	jnz start_not_dll_process_attach
;=========== dll process attach
;--------- alloc mem for stack emulator
	invoke VirtualAlloc, 0, EMUL_STACK_SIZE+64, MEM_COMMIT, PAGE_READWRITE
	add eax, 33
	mov pstack, eax
;---------- load vdb
	call InitVDB
;---------- load cure library
	invoke LoadLibrary, offset CureDllStr
	mov hCureLib, eax
	invoke GetProcAddress, eax, offset pProbPackStr
	mov pProbPacked, eax
;----------------------------
	xor eax, eax
	inc eax
	ret
;-----------------------
start_not_dll_process_attach :
	cmp fdwReason, DLL_PROCESS_DETACH
	jnz not_dll_process_deattach
;=========== dll process deattach
;------- free res
	invoke FreeLibrary, hCureLib
	call FreeVDB
	sub pstack, 33
	invoke VirtualFree, pstack, EMUL_STACK_SIZE+33, MEM_DECOMMIT
not_dll_process_deattach :
;=========== something other
	xor eax, eax
	inc eax
	ret

Start		ENDP

;=======================================================================;
;	Name	: FindFiles						;
;	Proto	: FindFiles(char *path)					;
;	Descr.	: Find files in path folder and in all subfolders	;
;	Ret	: 0 if succes, -1 if err				;
;=======================================================================;

FindFiles	PROC	curdir : dword ;, ext : dword
	local buff[BUFF_SIZE]  : byte
	local buff2[BUFF_SIZE]  : byte
	local hSrch : dword
	
	;-------- copy curdir to buff
	invoke lstrcpy, addr buff, curdir
	invoke lstrcat, addr buff, ext
	;-------- find files and dirs in curdir
	invoke FindFirstFile, addr buff, addr wfd
	mov hSrch, eax
	inc eax
	jnz find_first_ok
		dec eax
		ret
find_first_ok :
	invoke FindNextFile, hSrch, addr wfd	; we must skip fucked "." and ".." dirs
	invoke FindNextFile, hSrch, addr wfd	
	test eax, eax
	jz no_more_files
find_loop :
	;------------- process founded
		test wfd.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY
		jz not_directory
		;----- it is directory
			invoke lstrcpy, addr buff2, curdir
			invoke lstrcat, addr buff2, addr wfd.cFileName
			invoke lstrlen, addr buff2
			mov word ptr buff2[eax], 005ch
			invoke FindFiles, addr buff2
			jmp find_next
		;------ it is not directory
	not_directory :
		;--------- extennsions cmp loop
		invoke lstrlen, addr wfd.cFileName
		mov ecx, eax
		add eax, offset wfd.cFileName
		dec eax
		find_ext_loop :
			cmp byte ptr [eax], '.'
			jz end_find_ext_loop
			dec eax
			loop find_ext_loop		
		end_find_ext_loop :
			inc eax
			mov ecx, nmExtCounter
			test ecx, ecx
			jz in_list_of_exts_2
			mov ebx, pExt
		ext_cmp_loop :
				test ecx, ecx
				jz exit_ext_cmp_loop
				dec ecx
				push ecx
				push eax
				invoke lstrcmp, eax, ebx
				test eax, eax
				jz in_list_of_exts
				pop eax
				pop ecx
				add ebx, 30
			jmp ext_cmp_loop 
		exit_ext_cmp_loop :	
			jmp find_next
		in_list_of_exts :
			;----------- clear stack
			pop eax
			pop ebx
		in_list_of_exts_2 :
			;------------ check file
			invoke SendMessage, hMPB, PBM_STEPIT, 0, 0
			invoke lstrcpy, addr buff2, curdir
			invoke lstrcat, addr buff2, addr wfd.cFileName
			invoke Check, addr buff2
			
		;----- find next file/directory
	find_next :
		invoke FindNextFile, hSrch, addr wfd
		test eax, eax
		jnz find_loop
	;-------------- no more files
	no_more_files :
		invoke FindClose, hSrch
		xor eax, eax
	FindFiles_ret :
		ret
FindFiles	ENDP

;=======================================================================;
;	Name	: InitVDB						;
;	Proto	: InitVDB(void)						;
;	Descr.	: Load virus db into memory				;
;	Ret	: 0 if failure, address if succes			;
;=======================================================================;
InitVDB		PROC
	invoke CreateFile, offset SigLibStr, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	inc eax
	jz InitVDB_ret
	dec eax
	mov hfVdb, eax
	mov ebx, eax
	invoke GetFileSize, ebx, 0
	invoke CreateFileMapping, ebx, 0, PAGE_READONLY, 0, eax, 0
	mov hfMapVdb, eax
	test eax, eax
	jz InitVDB_ret
	invoke MapViewOfFile, eax, FILE_MAP_READ, 0, 0, 0
	test eax, eax
	jz InitVDB_ret
	mov pVDB, eax
	mov ecx, dword ptr [eax]
	mov VDBCounter, ecx
InitVDB_ret :
	ret
InitVDB		ENDP

;=======================================================================;
;	Name	: FreeVDB						;
;	Proto	: FreeVDB(void)						;
;	Descr.	: UnLoad virus db 					;
;	Ret	: 0 if failure, [1 ; 2^32-1] if succes			;
;=======================================================================;
FreeVDB		PROC
	invoke UnmapViewOfFile, pVDB
	invoke CloseHandle, hfMapVdb
	invoke CloseHandle, hfVdb
	mov pVDB, 0
	ret
FreeVDB		ENDP

;=======================================================================;
;	Name	: GetFCount						;
;	Proto	: GetFCount(char *dir)					;
;	Descr.	: Return nubmer of files in dir and subdirs		;
;	Ret	: -1 - error, [0;-1) - nubmer of files			;
;=======================================================================;
GetFCount	PROC	curdir : DWORD
	local buff[BUFF_SIZE]  : byte
	local buff2[BUFF_SIZE]  : byte
	local hSrch : dword
	;-------- copy curdir to buff
	invoke lstrcpy, addr buff, curdir
	invoke lstrcat, addr buff, ext
	;-------- find files and dirs in curdir
	invoke FindFirstFile, addr buff, addr wfd
	mov hSrch, eax
	inc eax
	jnz cfind_first_ok
		dec eax
		ret
cfind_first_ok :
	invoke FindNextFile, hSrch, addr wfd	; we must skip fucked "." and ".." dirs
	invoke FindNextFile, hSrch, addr wfd	
	test eax, eax
	jz cno_more_files
cfind_loop :
	;------------- process founded
		test wfd.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY
		jz cnot_directory
		;----- it is directory
			invoke lstrcpy, addr buff2, curdir
			invoke lstrcat, addr buff2, addr wfd.cFileName
			invoke lstrlen, addr buff2
			mov word ptr buff2[eax], 005ch
			invoke GetFCount, addr buff2
			jmp cfind_next
		;------ it is not directory
	cnot_directory :
		;--------- extennsions cmp loop
		invoke lstrlen, addr wfd.cFileName
		mov ecx, eax
		add eax, offset wfd.cFileName
		dec eax
		cfind_ext_loop :
			cmp byte ptr [eax], '.'
			jz cend_find_ext_loop
			dec eax
			loop cfind_ext_loop		
		cend_find_ext_loop :
			inc eax
			mov ecx, nmExtCounter
			test ecx, ecx
			jz cin_list_of_exts
			mov ebx, pExt
		cext_cmp_loop :
				test ecx, ecx
				jz cexit_ext_cmp_loop
				dec ecx
				push ecx
				push eax
				invoke lstrcmp, eax, ebx
				test eax, eax
				jz cin_list_of_exts
				pop eax
				pop ecx
				add ebx, 30
			jmp cext_cmp_loop 
		cexit_ext_cmp_loop :	
			jmp cfind_next
		cin_list_of_exts :
			inc fCounter
		;----- find next file/directory
	cfind_next :
		invoke FindNextFile, hSrch, addr wfd
		test eax, eax
		jnz cfind_loop
	;-------------- no more files
	cno_more_files :
		invoke FindClose, hSrch
		mov eax, fCounter
		ret
GetFCount	ENDP

;=======================================================================;
;	Name	: Scan							;
;	Proto	: Scan( byte *files, dword nFCounter, byte *pExts,  \	;
;			DWORD nExtCounter ) ;				;
;	Descr.	: Main function 					;
;	Ret	: 0 - succ, other - fuck				;
;=======================================================================;
Scan		PROC	pFiles : dword, nFCounter:dword, pExts : dword, nExtCounter : DWORD
local	nGFCounter : DWORD
	invoke SendMessage, hCurScanEdt, WM_SETTEXT, 0, offset PrepareToScan
;--------- create "last.rep" file
	invoke CreateFileA, offset LastRepStr, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
	mov hRepFile, eax
	inc eax
	jnz scan_rep_cr_ok
scan_error :
		or eax, -1
		ret
scan_rep_cr_ok :
;-------- are all loaded
	cmp pVDB, 0
	jz scan_error
	cmp pstack, 0
	jz scan_error
;-------- init vars
	push nExtCounter
	pop nmExtCounter
	push pExts
	pop pExt
;-------- get f count
	mov nGFCounter, 0
	mov ecx, nFCounter
	mov ebx, pFiles
get_f_count_loop :
	push ecx
	push ebx
	invoke lstrlen, ebx
	add eax, ebx
	cmp byte ptr [eax-1], '\'
	jnz get_f_count_not_a_dir
		mov edi, offset buffer
		mov esi, ebx
		mov ecx, BUFF_SIZE
		rep movsb
		invoke GetFCount, offset buffer
		add nGFCounter, eax
		jmp get_f_count_next
get_f_count_not_a_dir :
	inc nGFCounter
get_f_count_next :
	pop ebx
	pop ecx
	add ebx, 257
	loop get_f_count_loop
;-------- init ProgressBar ( SetRange)
	mov eax, nGFCounter
	invoke SendMessage, hMPB, PBM_SETRANGE32, 0, nGFCounter
	invoke SendMessage, hMPB, PBM_SETSTEP, 1, 0
;-------- start scan
	mov ecx, nFCounter
	mov ebx, pFiles
Scan_Loop :
	push ecx
	push ebx
	mov byte ptr [ebx+256], 1
	invoke lstrlen, ebx
	add eax, ebx
	cmp byte ptr [eax-1], '\'
	jz scan_directory 
	;------- scan file
		invoke Check, ebx
		jmp scan_next
scan_directory :
	;------- scan dir
		invoke FindFiles, ebx
scan_next :
	pop ebx
	inc eax
	jnz succ_scan
		mov byte ptr [ebx+256], 0
succ_scan :
	pop ecx
	add ebx, 257
	loop Scan_Loop
;-------- free virtual stack
	
;-------- ret
	xor eax, eax
	ret
Scan		ENDP


;=======================================================================;
;	Name	: EmualteCmd						;
;	Proto	: EmulateCmd( byte *pinst ) 				;
;	Descr.	: Emulate command 					;
;	Ret	: -1 - fuck, cmd length - succ				;
;=======================================================================;
EmulateCmd	PROC	pinst : DWORD
;--------- set emulator flagz
	mov are_3_ops, 0
	mov need_av_check, 0
;--------- fill cmdbuff with n0p
	cld
	mov ecx, 16
	mov edi, offset cmdbuff
	mov al, 090H
	rep stosb
;--------- prepare to fuck
	mov esi, pinst
	xor ecx, ecx
	mov prefixfl, 0
;--------- fuck =)
repeat_decode :
	lodsb
	inc ecx
;--------- are there normal instruction
	cmp ecx, 16
	jae EmulateCmd_UnknowInstr
;------ not emulate instructions
	cmp al, 0ECH
	jb not_no_emul_inst
	cmp al, 0EFH
	jbe EmulateCmd_UnknowInstr
not_no_emul_inst :
	
;------ try to find commandz with modrm
	cmp al, 00H		; add [--], al
	jz modrm_1
	cmp al, 01H		; add [--], eax
	jz modrm_1
	cmp al, 02H		; add al, [--]
	jz modrm_1
	cmp al, 03H		; add eax, [--]
	jz modrm_1
	cmp al, 08H		; or
	jz modrm_1
	cmp al, 09H		; or
	jz modrm_1
	cmp al, 0AH		; or 
	jz modrm_1
	cmp al, 0BH		; or
	jz modrm_1
	cmp al, 10H		; adc
	jz modrm_1
	cmp al, 11H		; adc
	jz modrm_1
	cmp al, 12H		; adc
	jz modrm_1
	cmp al, 13H		; afc
	jz modrm_1
	cmp al, 18H		; sbb
	jz modrm_1
	cmp al, 19H		; sbb
	jz modrm_1
	cmp al, 1AH		; sbb
	jz modrm_1
	cmp al, 1BH		; sbb
	jz modrm_1
	cmp al, 20H		; and
	jz modrm_1
	cmp al, 21H		; and
	jz modrm_1
	cmp al, 22H		; and
	jz modrm_1
	cmp al, 23H		; and
	jz modrm_1
	cmp al, 28H		; sub
	jz modrm_1
	cmp al, 29H		; sub
	jz modrm_1
	cmp al, 2AH		; sub
	jz modrm_1
	cmp al, 2BH		; sub
	jz modrm_1
	cmp al, 30H		; xor
	jz modrm_1
	cmp al, 31H		; xor
	jz modrm_1
	cmp al, 32H		; xor
	jz modrm_1
	cmp al, 33H		; xor
	jz modrm_1
	cmp al, 38H		; cmp
	jz modrm_1
	cmp al, 39H		; cmp
	jz modrm_1
	cmp al, 3AH		; cmp
	jz modrm_1
	cmp al, 3BH		; cmp
	jz modrm_1
	cmp al, 62H		; bound
	jz modrm_1		
	cmp al, 63H		; arpl
	jz modrm_1
	cmp al, 69H		; imul
	jz spec_81H
	cmp al, 6BH		; imul
	jz spec_82H
	;----- megashit
	cmp al, 80H
	jz spec_80H
	cmp al, 81H		; add/or/xor/and other shit
	jz spec_81H
	cmp al, 82H		; add/or/xor/and other shit
	jz spec_82H
	cmp al, 83H		; add/or/xor/and other shit
	jz spec_83H
	;-------------
	cmp al, 84H
	jb not_84H_8CH
	cmp al, 8CH
	jbe modrm_1
not_84H_8CH :
	cmp al, 8DH
	jz spec_@8DH
	cmp al, 8EH
	jz spec_@8EH
	cmp al, 8FH
	jz modrm_1
	cmp al, 0C0H		; rol
	jz spec_0C0H
	cmp al, 0C1H		; rol
	jz spec_0C1H
	cmp al, 0C4H		; les
	jz modrm_1
	cmp al, 0C5H		; lds
	jz modrm_1
	cmp al, 0C6H		; mov
	jz modrm_1
	cmp al, 0C7H		; mov
	jz modrm_1
	cmp al, 0D0H		; rol and other shit
	jz modrm_1
	cmp al, 0D1H		; rol and other shit
	jz modrm_1
	cmp al, 0D2H		; rol and other shit
	jz modrm_1
	cmp al, 0D3H		; rol and other shit
	jz modrm_1
	cmp al, 0D8H
	jb not_0D8H_0DFH	; [ 0D8H ; 0DFH ]
	cmp al, 0DFH
	jbe modrm_1
not_0D8H_0DFH :
	cmp al, 0F6H		; test / and other shit
	jz spec_@0F6H
	cmp al, 0F7H		; test / and other shit
	jz spec_@0F7H
	cmp al, 0FEH		; inc/dec
	jz spec_0FEH
	cmp al, 0FFH
	jz spec_0FFH
;------------ prefixes
	cmp al, 0F0H
	jz prefix_0F0H
	cmp al, 0F2H
	jz prefix_0F2H
	cmp al, 0F3H
	jz prefix_0F3H
	cmp al, 02EH
	jz prefix_02EH
	cmp al, 036H
	jz prefix_036H
	cmp al, 03EH
	jz prefix_03EH
	cmp al, 026H
	jz prefix_026H
	cmp al, 064H
	jz prefix_064H
	cmp al, 065H
	jz prefix_065H
	cmp al, 066H
	jz prefix_066H
	cmp al, 067H
	jz prefix_067H
;----------- stack commands and inc dec( push <reg>/pop<reg> pusha[d], popa[d], pushf, popf, inc <reg>, dec <reg> )
	cmp al, 03FH
	jb not_push_popr
	cmp al, 61H
	jbe stack_command
not_push_popr :
	cmp al, 09CH
	jz stack_command
	cmp al, 09DH
	jz stack_command
	cmp al, 0EH
	jz stack_command
	cmp al, 1EH
	jz stack_command
	cmp al, 1FH
	jz stack_command
	cmp al, 16H
	jz stack_command
	cmp al, 17H
	jz stack_command
	cmp al, 06H
	jz stack_command
	cmp al, 07H
	jz stack_command
;------------ simply command ( 1 byte without memory usage)
	cmp al, 90H
	jb not_xchg_regs
	cmp al, 99H
	jbe simply_command
not_xchg_regs :
	cmp al, 9BH
	jz simply_command
	cmp al, 9EH
	jz simply_command
	cmp al, 9FH
	jz simply_command
	cmp al, 37H
	jz simply_command
	cmp al, 2FH
	jz simply_command
	cmp al, 27H
	jz simply_command
	cmp al, 0D6H
	jz simply_command
	cmp al, 0F8H
	jb not_flag_command
	cmp al, 0FDH
	jbe simply_command
not_flag_command :
	cmp al, 0F5H
	jz simply_command
;---------- are it is 0FH ?
	cmp al, 0FH
	jnz not_0FH
		inc ecx
		lodsb
		;------------ what is cmd type ?
		cmp al, 00H
		jz spec_0FH_00H
		cmp al, 01H
		jz spec_0FH_01H
		cmp al, 03H
		jbe @0FH_modrm
		cmp al, 0FH
		jbe EmulateCmd_UnknowInstr
		cmp al, 17H
		jbe @0FH_modrm
		cmp al, 18H
		jz spec_0FH_18H
		cmp al, 1FH
		jbe EmulateCmd_UnknowInstr
		cmp al, 23H
		jbe spec_0FH_20H_23H
		cmp al, 26H
		jbe EmulateCmd_UnknowInstr			; Probably 26 and 24 is normal instructions !
		cmp al, 2FH
		jbe @0FH_modrm
		cmp al, 31H
		jz @0FH_simply_command				; Probably need additional table of tics !
		cmp al, 3FH
		jbe EmulateCmd_UnknowInstr			; [40 ; 6FH]
		cmp al, 6FH
		jbe @0FH_modrm
		cmp al, 70H
		jz @0FH_modrm
		cmp al, 71H
		jz spec_0FH_71H
		cmp al, 72H
		jz spec_0FH_72H
		cmp al, 78H
		jbe @0FH_modrm
		cmp al, 7BH
		jbe EmulateCmd_UnknowInstr
		cmp al, 7FH
		jbe @0FH_modrm
		cmp al, 8FH
		jbe @0FH_jxx_cmd
		cmp al, 9FH
		jbe @0FH_modrm
		cmp al, 0A1H
		jbe @0FH_stack_command
		cmp al, 0A2H
		jz @0FH_simply_command
		cmp al, 0A5H
		jbe @0FH_modrm
		cmp al, 0A7H
		jbe EmulateCmd_UnknowInstr
		cmp al, 0ADH
		jbe @0FH_modrm
		cmp al, 0AEH
		jz spec_0FH_0AEH
		cmp al, 0AFH
		jz @0FH_modrm
		cmp al, 0B7H
		jbe @0FH_modrm
		cmp al, 0B8H
		jz EmulateCmd_UnknowInstr
		cmp al, 0B9H
		jz EmulateCmd_UnknowInstr		;jz spec_0FH_0B9H ; pobably
		cmp al, 0BAH
		jz spec_0FH_0BAH
		cmp al, 0BFH
		jbe @0FH_modrm
		cmp al, 0C1H
		jbe @0FH_modrm
		;cmp al, 0C6H
		;------------- here i stoped. Add instructions up to 0fffh =)
		;------ if unknow instruction
		jmp EmulateCmd_UnknowInstr
	;=============================== @0FH_modrm
		@0FH_modrm_1_bad_addr :
			xor eax, eax
			dec eax
			ret
		@0FH_modrm :
			mov need_av_check, 1
			mov main_opcode, al
			inc ecx
			;------- get length
			lodsb
		@0FH_spec_2_modrmb_1 :
			mov modrmb, al
			mov bl, al		; bl will be mod
			and bl, 11000000b
			mov bh, al		; bh will be reg
			and bh, 00111000b
			mov ah, al
			and ah, 00000111b	; ah will be r/m
			;----- what mod ?
			cmp bl, 00000000b
			jnz @0FH_not_register_mode2
					test prefixfl, 0001000000000000b
					jnz @0FH_@67H
					;-------- 32 bit add mode calculations
						;----- are sib or imm addr
						cmp ah, 00000100b
						jz @0FH_sib_shit_1
						cmp ah, 00000101b
						jz @0FH_im32_1
						;------ if simply register
						xor edx, edx
						test prefixfl, 0000001000000000b
						jz @0FH_no_@00_simp_reg_66H
							mov byte ptr cmdbuff[0], 66H
							inc edx
					@0FH_no_@00_simp_reg_66H :
						mov cmdbuff[edx], 0FH
						inc edx
						movzx eax, ah
						shl eax, 2	; imul eax, eax, 4
						mov ebx, regz[eax]
						invoke GetRealAddress, ebx	; rl addr in ebx
						inc ebx
						jz @0FH_modrm_1_bad_addr
						dec ebx
						mov al, main_opcode
						mov cmdbuff[edx+0], al
						mov al, modrmb
						and al, 00111000b
						or al,  00000101b
						mov cmdbuff[edx+1], al
						mov dword ptr cmdbuff[edx+2], ebx
						cmp are_3_ops, 00000001b
						jz @0FH_@00_3_ops_byte
						cmp are_3_ops, 00000010b
						jz @0FH_@00_3_ops_dword
						jmp emulate_it
					;---- if special cmd with 1 byte op
					@0FH_@00_3_ops_byte :
							lodsb
							inc ecx
							mov cmdbuff[edx+6], al
							jmp emulate_it
					;----- if special cmd with dword op
					@0FH_@00_3_ops_dword :
						;------ are there 66h prefix
						;------ no
							test prefixfl, 0000001000000000b
							jnz  @0FH_@00_3_ops_dword_66H
								lodsd
								add ecx, 4
								mov dword ptr cmdbuff[edx+6], eax
								jmp emulate_it
						;------- yes
						@0FH_@00_3_ops_dword_66H :
								lodsw
								add ecx, 2
								mov word ptr cmdbuff[edx+6], ax
								jmp emulate_it
							
						;------ if there sib
					@0FH_sib_shit_1 :
						inc ecx
						xor eax, eax
						lodsb
						movzx ebx, al
						and ebx, 00011100b
						shl ebx, 2
						mov ebx, regz[ebx]
						movzx edx, al
						and edx, 11100000b
						shl edx, 2
						mov edx, regz[edx]
						and al, 00000011b
						xchg eax, ecx
						shl edx, cl
						xchg eax, ecx
						add ebx, edx
						invoke GetRealAddress, ebx	; rl addr in ebx
						inc ebx
						jz @0FH_modrm_1_bad_addr
						xor edx, edx
						test prefixfl, 0000001000000000b
						jz @0FH_not_@00_sib_66H
							mov byte ptr [edx], 66H
							inc edx
					@0FH_not_@00_sib_66H :
						mov cmdbuff[edx], 0FH
						inc edx
						mov al, main_opcode
						mov cmdbuff[edx+0], al
						mov al, modrmb
						and al, 00111000b
						or al,  00000101b
						mov cmdbuff[edx+1], al
						mov dword ptr cmdbuff[edx+2], ebx
						cmp are_3_ops, 1
						jz @0FH_@00_sib_3_ops_byte
						cmp are_3_ops, 2
						jz @0FH_@00_sib_3_ops_dword
							jmp emulate_it
							;------ 3 ops byte
						@0FH_@00_sib_3_ops_byte :
							lodsb
							inc ecx
							mov cmdbuff[edx+3], al
							jmp emulate_it
							;------ 3 ops dword
						@0FH_@00_sib_3_ops_dword :
								;---- are there fucked 66H prefix ?
							test prefixfl, 0000001000000000b
							jnz @0FH_@00_sib_3_ops_dword_66H
								lodsd
								add ecx, 4
								mov dword ptr cmdbuff[edx+6], eax
								jmp emulate_it
						@0FH_@00_sib_3_ops_dword_66H :
								lodsw
								add ecx, 2
								mov word ptr cmdbuff[edx+6], ax
								jmp emulate_it
							
						;------ if im32
					@0FH_im32_1 	 :
						add ecx, 4
						lodsd
						invoke GetRealAddress, eax
						inc ebx
						jz @0FH_modrm_1_bad_addr
						dec ebx
						test prefixfl, 0000001000000000b
						jnz @0FH_im32_1_66H_prefx
							mov cmdbuff[0], 0FH
							mov dl, main_opcode
							mov cmdbuff[1], dl
							mov dl, modrmb
							mov cmdbuff[2], dl
							mov dword ptr cmdbuff[3], ebx
							cmp are_3_ops, 1
							jz @0FH_@00_im32_3_ops_byte_no66H
							cmp are_3_ops, 2
							jz @0FH_@00_im32_3_ops_dword_no66H
							jmp emulate_it
							@0FH_@00_im32_3_ops_byte_no66H :
								lodsb
								inc ecx
								mov cmdbuff[7], al
								jmp emulate_it
							@0FH_@00_im32_3_ops_dword_no66H :
								lodsd
								add ecx, 4
								mov dword ptr cmdbuff[7], eax
								jmp emulate_it
						@0FH_im32_1_66H_prefx :
							mov dl, main_opcode
							mov cmdbuff[0], 0FH
							mov cmdbuff[1], 66H
							mov cmdbuff[2], dl
							mov dl, modrmb
							mov cmdbuff[3], dl
							mov dword ptr cmdbuff[4], ebx
							cmp are_3_ops, 1
							jz @0FH_@00_im3_3_opd_byte_66H
							cmp are_3_ops, 2
							jz @0FH_@00_im3_3_opd_dword_66H
							jmp emulate_it
						@0FH_@00_im3_3_opd_byte_66H :
								lodsb
								inc ecx
								mov  cmdbuff[8], al
								jmp emulate_it
						@0FH_@00_im3_3_opd_dword_66H :
								lodsw
								add ecx, 2
								mov word ptr cmdbuff[8], ax
								jmp emulate_it
								
						
				;-------- 16 bit mode calculations
				@0FH_@67H :
					xor eax, eax		; don't suported yet
					dec eax
					ret
					
				
				
		@0FH_not_register_mode2 :
		;------------- are there simply registers ?
			cmp bl, 11000000b
			jnz @0FH_not_register_mode
				xor edx, edx
				test prefixfl, 0000001000000000b
				jz @0FH_@not_11H_66H
					mov cmdbuff[edx], 66H
					inc edx
			@0FH_@not_11H_66H :
				mov cmdbuff[edx], 0FH
				inc edx
				mov al, main_opcode
				mov cmdbuff[edx], al
				mov al, modrmb
				mov cmdbuff[edx+1], al
				cmp are_3_ops, 1
				jz @0FH_@11_3_ops_byte
				cmp are_3_ops, 2
				jz @0FH_@11_3_ops_dword
				jmp emulate_it
				;----- byte 
				@0FH_@11_3_ops_byte :
					lodsb
					inc ecx
					mov cmdbuff[edx+2], al
					jmp emulate_it
				;----- dword or word
				@0FH_@11_3_ops_dword :
					test prefixfl, 0000001000000000b
					jnz @11_3_ops_dword_66H
						lodsd
						add ecx, 4
						mov dword ptr cmdbuff[edx+2], eax
						jmp emulate_it
				@0FH_@11_3_ops_dword_66H :
						lodsw
						add ecx, 2
						mov word ptr cmdbuff[edx+2], ax
						jmp emulate_it
		@0FH_not_register_mode :
		;------------ are there off32( mod = 2) ?
			cmp bl, 10000000b
			jnz not_10B
				test ah, 00000101b
				jnz @10B_SIB
				add ecx, 4
			;------ all right. there no sib
				movzx ebx, ah
				shl ebx, 2
				lodsd
				mov ebx, regz[ebx]
				add ebx, eax
				invoke GetRealAddress, ebx
				inc ebx
				jz @0FH_modrm_1_bad_addr
				dec ebx
					xor edx, edx
					test prefixfl, 0000001000000000b
					jz @0FH_@not_10_66H
						mov cmdbuff[edx], 66H
						inc edx
				@0FH_@not_10_66H :
					mov cmdbuff[edx], 0FH
					inc edx
					mov al, main_opcode
					mov cmdbuff[edx+0], al
					mov al, modrmb
					and al, 00111000b
					or al,  00000101b
					mov cmdbuff[edx+1], al
					mov dword ptr cmdbuff[2], ebx
					cmp are_3_ops, 1
					jz @0FH_@10_3_ops_byte
					cmp are_3_ops, 2
					jz @0FH_@10_3_ops_dword
					jmp emulate_it
					;---- byte
					@0FH_@10_3_ops_byte :
						lodsb
						inc ecx
						mov cmdbuff[edx+6], al
						jmp emulate_it
					;---- dword
					@0FH_@10_3_ops_dword :
						test prefixfl, 0000001000000000b
						jnz @0FH_@10_3_ops_word
						lodsd
						add ecx, 4
						mov dword ptr cmdbuff[edx+6], eax
						jmp emulate_it
					;---- word
					@0FH_@10_3_ops_word :
						lodsw
						add ecx, 2
						mov word ptr cmdbuff[edx+6], ax
						jmp emulate_it
			;------ shit. There SIB byte
			@0FH_@10B_SIB :
				lodsb
				movzx ebx, al
				and ebx, 00011100b
				shl ebx, 2
				mov ebx, regz[ebx]
				movzx edx, al
				and edx, 11100000b
				shl edx, 2
				mov edx, regz[edx]
				and al, 00000011b
				xchg eax, ecx
				shl edx, cl
				xchg eax, ecx
				add edx, ebx
				add ecx, 5
				lodsd
				add edx, eax
				invoke GetRealAddress, edx
				inc ebx
				jz @0FH_modrm_1_bad_addr
				dec ebx
				xor edx, edx
				test prefixfl, 0000001000000000b
				jz @0FH_@10B_SIB_NO_66H
					mov cmdbuff[edx], 66H
					inc edx
			@0FH_@10B_SIB_NO_66H :
				mov cmdbuff[edx], 0FH
				inc edx
				mov al, main_opcode
				mov cmdbuff[edx+0], al
				mov al, modrmb
				and al, 00111000b
				or al,  00000101b
				mov cmdbuff[edx+1], al
				mov dword ptr cmdbuff[edx+2], ebx
				cmp are_3_ops, 1
				jz @0FH_@10_sib_3_ops_byte
				cmp are_3_ops, 2
				jz @0FH_@10_sib_3_ops_dword
				jmp emulate_it
				;---- byte 
				@0FH_@10_sib_3_ops_byte :
					lodsb
					inc ecx
					mov cmdbuff[edx+6], al
					jmp emulate_it
				;---- dword
				@0FH_@10_sib_3_ops_dword :
					test prefixfl, 0000001000000000b
					jnz @0FH_@10_sib_3_ops_word
					lodsd
					add ecx, 4
					mov dword ptr cmdbuff[edx+6], eax
					jmp emulate_it
				;---- word
				@0FH_@10_sib_3_ops_word :
					lodsw
					add ecx, 2
					mov dword ptr cmdbuff[edx+6], eax
					jmp emulate_it
		@0FH_not_10B :
		;---------- yeah. It is of course simple off8
			test ah, 00000101b
			jnz @0FH_@01B_SIB
		;------ if there no sib byte
			inc ecx
			movzx eax, ah
			shl eax, 2	; imul eax, eax, 4
			mov ebx, regz[eax]
			lodsb
			cbw
			cwde
			add ebx, eax
			invoke GetRealAddress, ebx
			inc ebx
			jz @0FH_modrm_1_bad_addr
			dec ebx
			xor edx, edx
			test prefixfl, 0000001000000000b
			jz @0FH_@10B_no_66H
				mov cmdbuff[edx], 66H
				inc edx
		@0FH_@10B_no_66H :
			mov cmdbuff[edx], 0FH
			inc edx
			mov al, main_opcode
			mov cmdbuff[edx+0], al
			mov al, modrmb
			and al, 00111000b
			or al,  00000101b
			mov cmdbuff[edx+1], al
			mov dword ptr cmdbuff[edx+2], ebx
			cmp are_3_ops, 1
			jz @0FH_@01_3_ops_byte
			cmp are_3_ops, 2
			jz @0FH_@01_3_ops_dword
			jmp emulate_it
			;----- if additional op byte
			@0FH_@01_3_ops_byte :
				lodsb
				inc ecx
				mov byte ptr cmdbuff[edx+6], al
				jmp emulate_it
			;----- if additional op dword
			@0FH_@01_3_ops_dword :
				test prefixfl, 0000001000000000b
				jnz @0FH_@01_3_ops_word
				lodsd
				add ecx, 4
				mov dword ptr cmdbuff[edx+6], eax
				jmp emulate_it
			@0FH_@01_3_ops_word :
				lodsw
				add ecx, 2
				mov dword ptr cmdbuff[edx+6], eax
				jmp emulate_it
		;------ if there sib		
		@0FH_@01B_SIB :
			lodsb
			movzx ebx, al
			and ebx, 00011100b
			shl ebx, 2
			mov ebx, regz[ebx]
			movzx edx, al
			and edx, 11100000b
			shl edx, 2
			mov edx, regz[edx]
			and al, 00000011b
			xchg eax, ecx
			shl edx, cl
			xchg eax, ecx
			add edx, ebx
			add ecx, 2
			lodsb
			cbw
			cwde
			add edx, eax
			invoke GetRealAddress, edx
			inc ebx
			jz @0FH_modrm_1_bad_addr
			dec ebx
			xor edx, edx
			test prefixfl, 0000001000000000b
			jz @0FH_@01_no_66H
				mov cmdbuff[edx], 66H
				inc edx
		@0FH_@01_no_66H : 
			mov cmdbuff[edx], 0FH
			inc edx
			mov al, main_opcode
			mov cmdbuff[edx+0], al
			mov al, modrmb
			and al, 00111000b
			or al,  00000101b
			mov byte ptr cmdbuff[edx+1], al
			mov dword ptr cmdbuff[edx+2], ebx
			cmp are_3_ops, 1
			jz @0FH_@01_sib_3_ops_byte
			cmp are_3_ops, 2
			jz @0FH_@01_sib_3_ops_dword
			jmp emulate_it
			;---- byte
			@0FH_@01_sib_3_ops_byte :
				lodsb
				inc ecx
				mov byte ptr cmdbuff[edx+6], al
				jmp emulate_it
			;---- dword
			@0FH_@01_sib_3_ops_dword :
				test prefixfl, 0000001000000000b
				jnz @01_sib_3_ops_word
				lodsd
				add ecx, 4
				mov dword ptr cmdbuff[6], eax
				jmp emulate_it
			@0FH_@01_sib_3_ops_word :
				lodsw
				add ecx, 2
				mov word ptr cmdbuff[edx+6], ax
				jmp emulate_it
		;====================== @0FH_simply_command
		@0FH_stack_command :
			mov need_av_check, 1
		@0FH_simply_command :
			mov main_opcode, al
			xor edx, edx
			test prefixfl, 0000001000000000b
			jz @0FH_simply_cmd_not_66H_pref
				mov cmdbuff[edx], 066H
				inc edx
		@0FH_simply_cmd_not_66H_pref :
			mov cmdbuff[edx], 0FH
			mov cmdbuff[edx+1], al
			mov edx, dword ptr regz[16]
			mov last_addr, edx
			mov eax, [edx]
			mov dword ptr OldData[0], eax
			jmp emulate_it
		;======================== @0FH_jxx_cmd
		@0FH_jxx_cmd :
			add ecx, 4
			mov main_opcode, al
			mov @0FH_jxx_jump_or_no[1], al
			push flagz
			popfd
			xchg ecx, regz[4]
		@0FH_jxx_jump_or_no DB 0FH, 80H, 05H, 00H, 00H, 00H
			jmp no_jump
			xchg ecx, regz[4]
			lodsd
			add eax, ecx
			mov ebx, cur_eip
			sub ebx, pRealPE
			add ebx, inh.OptionalHeader.ImageBase
			add ebx, eax
			invoke GetRealAddress, ebx
			inc ebx
			jz EmulateCmd_TotalError
			dec ebx
			mov cur_eip, ebx
			mov eax, ecx
			mov need_av_check, 0
			ret
		@0FH_no_jump :
			xchg ecx, regz[4]
			add cur_eip, ecx
			mov eax, ecx
			ret
		;====================== @0FH_00H	
		spec_0FH_00H :
			mov main_opcode, al
			lodsb
			dec esi
			and al, 00111000b
			cmp al, 00110000b
			jae EmulateCmd_UnknowInstr
			mov al, main_opcode
			jmp @0FH_modrm
		;====================== @0FH_01H	
		spec_0FH_01H :
			mov main_opcode, al
			lodsb
			dec esi
			and al, 00111000b
			cmp al, 00101000b
			jz EmulateCmd_UnknowInstr
			mov al, main_opcode
			jmp @0FH_modrm
		;====================== @0FH_71H
		;====================== @0FH_72H
		spec_0FH_71H :
		spec_0FH_72H :
			mov bl, al
			lodsb
			xchg al, bl
			dec esi
			and bl, 00111000b
			cmp bl, 00010000b
			jz spec_0FH_71H_emul_it
			cmp bl, 00100000b
			jz spec_0FH_71H_emul_it
			cmp bl, 00110000b
			jz spec_0FH_71H_emul_it
			jmp EmulateCmd_UnknowInstr
		spec_0FH_71H_emul_it :
			jmp @0FH_modrm
		;======================== @0FH_20H_23H
		spec_0FH_20H_23H :
			xor eax, eax
			dec eax
			ret
		;======================== @0FH_AEH
		spec_0FH_0AEH :
			mov bl, al
			lodsb
			dec esi
			xchg al, bl
			and bl, 11000000b
			jnz EmulateCmd_UnknowInstr
			jmp @0FH_modrm
		;======================== @0FH_18H
		spec_0FH_18H :
			mov bl, al
			lodsb
			dec esi
			xchg al, bl
			and bl, 00111000b
			cmp bl, 00100000b
			ja EmulateCmd_UnknowInstr
			jmp @0FH_modrm
		;======================== @0FH_0BAH
		spec_0FH_0BAH :
			mov bl, al
			lodsb
			dec esi
			xchg al, bl
			and bl, 11000000b
			cmp bl, 00100000b
			jna EmulateCmd_UnknowInstr
			mov are_3_ops, 1
			jmp @0FH_modrm
not_0FH :
;---------- simply command 2 operandz without ram usage
	cmp al, 04H
	jz simply_command_2_im8
	cmp al, 05H
	jz simply_command_2_im32
	cmp al, 0CH
	jz simply_command_2_im8
	cmp al, 0DH
	jz simply_command_2_im32
	cmp al, 14H
	jz simply_command_2_im8
	cmp al, 15H
	jz simply_command_2_im32
	cmp al, 1CH
	jz simply_command_2_im8
	cmp al, 1DH
	jz simply_command_2_im32
	cmp al, 24H
	jz simply_command_2_im8
	cmp al, 25H
	jz simply_command_2_im32
	cmp al, 2CH
	jz simply_command_2_im8
	cmp al, 2DH
	jz simply_command_2_im32
	cmp al, 34H
	jz simply_command_2_im8
	cmp al, 35H
	jz simply_command_2_im32
	cmp al, 3CH
	jz simply_command_2_im8
	cmp al, 3DH
	jz simply_command_2_im32
	cmp al, 68H
	jz simply_command_2_im32
	cmp al, 6AH
	jz simply_command_2_im8
	cmp al, 0A8H
	jz simply_command_2_im8
	cmp al, 0A9H
	jz simply_command_2_im32
	cmp al, 0B0H			;[  0B0H ; 0B7H ]
	jb not_0B0H_0B7H
	cmp al, 0B7H
	jbe simply_command_2_im8
not_0B0H_0B7H :
	cmp al, 0B8H			;[  0B8H ; 0BFH ]
	jb not_0B8H_0BFH
	cmp al, 0BFH
	jbe simply_command_2_im32
not_0B8H_0BFH :
	cmp al, 0D4H
	jz simply_command_2_im8
	cmp al, 0D5H
	jz simply_command_2_im8
;----------- jxx im8
	cmp al, 70H
	jb not_jxx_cmd
	cmp al, 7FH
	jbe jxx_cmd
not_jxx_cmd :
	cmp al, 0EBH
	jz jxx_cmd
	cmp al, 0E0H
	jb not_loopx_cmd
	cmp al, 0E3H
	jbe jxx_cmd
not_loopx_cmd :
;----------- direct ia32 addr for eax
	cmp al, 0A0H
	jb not_dir_ia32_addr
	cmp al, 0A3H
	jbe dir_ia_32_addr
not_dir_ia32_addr :
;------------- can't emulate instructions
	;---- in / out
	cmp al, 06CH
	jb not_cemul_1
	cmp al, 06FH
	jbe EmulateCmd_TotalError
not_cemul_1 :
	cmp al, 0E4H
	jb not_cemul_2
	cmp al, 0E7H
	jbe EmulateCmd_TotalError
not_cemul_2 :
	;----- int
	cmp al, 0CCH			; int <byte>
	jb not_cemul_3
	cmp al, 0CEH
	jbe EmulateCmd_TotalError
not_cemul_3 :
	cmp al, 0F1H			; int1
	jz EmulateCmd_TotalError
	cmp al, 0F4H			; hlt
	jz EmulateCmd_TotalError
;------------- diferent calls and so on shit
	cmp al, 0E8H			; rel call
	jz rel_calln_emul
	cmp al, 0E9H			; rell jmp
	jz rel_jmpn_emul
	cmp al, 0EAH
	jz jmpf_emul
	cmp al, 09AH
	jz callf_emul
;-------------- rets
	cmp al, 0C2H
	jz retN_emul_0C2H
	cmp al, 0C3H
	jz retN_emul_0C3H
	cmp al, 0CAH
	jz retf_emul
	cmp al, 0CBH
	jz retf_emul_op
;------------ strings instructions
	cmp al, 0A4H
	jz @0A4H
	cmp al, 0A5H
	jz @0A5H
	cmp al, 0A6H
	jz @0A6H
	cmp al, 0A7H
	jz @0A7H
	cmp al, 0AAH
	jz @0AAH
	cmp al, 0ABH
	jz @0ABH
	cmp al, 0ACH
	jz @0ACH
	cmp al, 0ADH
	jz @0ADH
	cmp al, 0AEH
	jz @0AEH
	cmp al, 0AFH
	jz @0AFH
;------------ XLAT
	cmp al, 0D7H
	jz @0D7H
;------------ unknow instruction
EmulateCmd_TotalError :
EmulateCmd_UnknowInstr :
	xor eax, eax
	dec eax
	ret
;########################################## retf emul ###########################################;
retf_emul :
	xchg esp, regz[16]
	pop ebx
	pop ax
	xchg esp, regz[16]
	mov dx, cx
	cmp ax, dx
	jnz EmulateCmd_TotalError
	invoke GetRealAddress, ebx
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov cur_eip, ebx
	mov need_av_check, 1
	mov eax, regz[16]
	mov last_addr, eax
	mov eax, ecx
	ret
retf_emul_op :
	xchg esp, regz[16]
	pop ebx
	pop ax
	lodsb
	movzx ecx, cl
	add esp, ecx
	xchg esp, regz[16]
	mov dx, cx
	cmp ax, dx
	jnz EmulateCmd_TotalError
	invoke GetRealAddress, ebx
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov cur_eip, ebx
	mov need_av_check, 1
	mov eax, regz[16]
	mov last_addr, eax
	mov eax, ecx
	ret
	
	
;########################################## callf emul ###########################################;
callf_emul :
	add ecx, 6
	lodsd
	mov ebx, eax
	lodsw
	mov dx, cs
	cmp ax, dx
	jnz EmulateCmd_TotalError
	xchg esp, regz[16]
	push cs
	push ebx
	xchg esp, regz[16]
	invoke GetRealAddress, ebx
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov need_av_check, 0
	mov cur_eip, ebx
	mov eax, ecx
	ret
;########################################## jmpf emul ###########################################;
jmpf_emul :
	add ecx, 6
	lodsd
	mov ebx, eax
	lodsw
	mov dx, cs
	cmp ax, dx
	jnz EmulateCmd_TotalError
	invoke GetRealAddress, ebx
	inc ebx
	mov need_av_check, 0
	jz EmulateCmd_TotalError
	dec ebx
	mov cur_eip, ebx
	mov eax, ecx
	ret
	
;########################################## 0FFH #################################################;
cj_modrm_1_bad_addr :
cj_emull_bad_addr :
	xor eax, eax
	dec eax
	ret
FFH_simply_emul :
	dec ecx
	dec esi
	jmp modrm_1
spec_0FFH :
	;----- if fucked 67H
	test prefixfl, 0001000000000000b
	jnz cj_@67H
	;--------
	mov bl, al
	and bl, 00111000b
	;test bl, 00111000b
	;jnz EmulateCmd_UnknowInstr
	cmp bl, 00001000b
	jbe modrm_1
	cmp bl, 00110000b
	jz modrm_1
;===================== spec modrm for call and jmp
	mov main_opcode, al
	inc ecx
	;------- get length
	lodsb
	mov modrmb, al
	mov bl, al		; bl will be mod
	and bl, 11000000b
	mov bh, al		; bh will be reg
	and bh, 00111000b
	mov ah, al
	and ah, 00000111b	; ah will be r/m
	;----- what command ? Can it be simply emulated ?
	cmp bh, 00000000b
	jz FFH_simply_emul
	cmp bh, 00001000b
	jz FFH_simply_emul
	cmp bh, 00011000b
	jz FFH_simply_emul
	cmp bh, 00111000b
	jz EmulateCmd_UnknowInstr
	;----- what mod ?
	cmp bl, 00000000b
	jnz cj_not_register_mode2
			test prefixfl, 0001000000000000b
			jnz cj_@67H
			;-------- 32 bit add mode calculations
				;----- are sib or imm addr
				cmp ah, 00000100b
				jz cj_sib_shit_1
				cmp ah, 00000101b
				jz cj_im32_1
				;------ if simply register
				movzx eax, ah
				shl eax, 2	; imul eax, eax, 4
				mov edx, regz[eax]
				push ebx
				invoke GetRealAddress, edx	; rl addr in ebx
				mov edx, ebx
				pop ebx
				inc edx
				jnz cj_emulation_ok_0
					xor eax, eax
					dec eax
					ret
			cj_emulation_ok_0 :
				dec edx
				cmp bh, 00010000b
				jz cj_emul_calln_00
				cmp bh, 00011000b
				jz cj_emul_callf_00
				cmp bh, 00100000b
				jz cj_emul_jmpn_00
				cmp bh, 00101000b
				jz cj_emul_jmpfn_00
				;---- emul calln
			cj_emul_calln_00 :
					mov ebx, dword ptr [edx]
					invoke GetRealAddress, ebx
					mov need_av_check, 0
					inc ebx
					jz cj_emull_bad_addr
					dec ebx
					mov cur_eip, ebx
					sub ebx, pRealPE
					add ebx, inh.OptionalHeader.ImageBase
					xchg esp, regz[16]
					push ebx
					xchg esp, regz[16]
					mov eax, ecx
					ret
				;---- emul callf
			cj_emul_callf_00 :
					mov ax, word ptr [edx+4]
					mov bx, cs
					cmp ax, bx
					jnz cj_emull_bad_addr
					mov ebx, dword ptr [edx]
					mov edx, ebx
					invoke GetRealAddress, ebx
					mov need_av_check, 0
					inc ebx
					jz cj_emull_bad_addr
					dec ebx
					xchg esp, regz[16]
					push ax
					push edx
					xchg esp, regz[16]
					mov cur_eip, ebx
					mov eax, ecx
					ret
				;------ jmpn
			cj_emul_jmpn_00:	
					mov ebx, dword ptr [edx]
					invoke GetRealAddress, ebx
					mov need_av_check, 0
					inc ebx
					jz cj_emull_bad_addr
					dec ebx
					mov cur_eip, ebx
					mov eax, ecx
					ret
				;------ jmpf
			cj_emul_jmpfn_00 :
					mov ax, word ptr [edx+4]
					mov bx, cs
					cmp ax, bx
					jnz cj_emull_bad_addr
					mov ebx, dword ptr [edx]
					mov edx, ebx
					invoke GetRealAddress, ebx
					mov need_av_check, 0
					inc ebx
					jz cj_emull_bad_addr
					dec ebx
					xchg esp, regz[16]
					push cs
					push edx
					xchg esp, regz[16]
					mov cur_eip, ebx
					mov eax, ecx
					ret
					
				;------ if there sib
			cj_sib_shit_1 :
				push ebx
				inc ecx
				xor eax, eax
				lodsb
				movzx ebx, al
				and ebx, 00000111b
				shl ebx, 2
				mov ebx, regz[ebx]
				movzx edx, al
				and edx, 00111000b
				shr edx, 1
				mov edx, regz[edx]
				and al, 11000000b
				xchg eax, ecx
				shl edx, cl
				xchg eax, ecx
				add ebx, edx
				invoke GetRealAddress, ebx	; rl addr in ebx
				mov need_av_check, 0
				inc ebx
				jz cj_emull_bad_addr
				xchg ebx, edx
				pop ebx
				cmp bh, 00010000b
				jz cj_emul_calln_00
				cmp bh, 00011000b
				jz cj_emul_callf_00
				cmp bh, 00100000b
				jz cj_emul_jmpn_00
				cmp bh, 00101000b
				jz cj_emul_jmpfn_00
				;------ if im32
			cj_im32_1 	 :
				add ecx, 4
				lodsd
				push ebx
				invoke GetRealAddress, eax
				mov need_av_check, 0
				inc ebx
				jz cj_emull_bad_addr
				dec ebx
				xchg ebx, edx
				pop ebx
				cmp bh, 00010000b
				jz cj_emul_calln_00
				cmp bh, 00011000b
				jz cj_emul_callf_00
				cmp bh, 00100000b
				jz cj_emul_jmpn_00
				cmp bh, 00101000b
				jz cj_emul_jmpfn_00
				
		;-------- 16 bit mode calculations
		cj_@67H :
			xor eax, eax		; don't suported yet
			dec eax
			ret
cj_not_register_mode2 :
;------------- are there simply registers ?
	cmp bl, 11000000b
	jnz cj_not_register_mode
		cmp bh, 00011000b
		jz EmulateCmd_UnknowInstr
		cmp bh, 00101000b
		jz EmulateCmd_UnknowInstr
		movzx ebx, ah
		shl ebx, 2
		mov edx, regz[ebx]
		invoke GetRealAddress, edx
		mov need_av_check, 0
		inc ebx
		jz cj_emull_bad_addr
		dec ebx
		mov cur_eip, ebx
		cmp bh, 00010000b
		jnz cj_not_calln_reg_mod
		xchg esp, regz[16]
		push edx
		xchg esp, regz[16]
	cj_not_calln_reg_mod :
		mov eax, ecx
		ret
cj_not_register_mode :
;------------ are there off32( mod = 2) ?
	cmp bl, 10000000b
	jnz cj_not_10B
		test ah, 00000101b
		jz cj_@10B_SIB
		add ecx, 4
	;------ all right. there no sib
		movzx ebx, ah
		shl ebx, 2
		lodsd
		mov ebx, regz[ebx]
		add ebx, eax
		invoke GetRealAddress, ebx
		mov need_av_check, 0
		inc ebx
		jz cj_emull_bad_addr
		dec ebx
		cmp bh, 00010000b
		jz cj_emul_calln_00
		cmp bh, 00011000b
		jz cj_emul_callf_00
		cmp bh, 00100000b
		jz cj_emul_jmpn_00
		cmp bh, 00101000b
		jz cj_emul_jmpfn_00
		
	;------ shit. There SIB byte
	cj_@10B_SIB :
		lodsb
		movzx ebx, al
		and ebx, 00011100b
		shl ebx, 2
		mov ebx, regz[ebx]
		movzx edx, al
		and edx, 11100000b
		shl edx, 2
		mov edx, regz[edx]
		and al, 00000011b
		xchg eax, ecx
		shl edx, cl
		xchg eax, ecx
		add edx, ebx
		add ecx, 5
		lodsd
		add edx, eax
		invoke GetRealAddress, edx
		mov need_av_check, 0
		inc ebx
		jz cj_modrm_1_bad_addr
		dec ebx
		mov dl, main_opcode
		mov cmdbuff[0], dl
		mov al, modrmb
		and al, 00111000b
		or al,  00000101b
		mov cmdbuff[1], al
		mov dword ptr cmdbuff[2], ebx
		jmp emulate_it
		
cj_not_10B :
;---------- yeah. It is of course simple off8
	test ah, 00000101b
	jnz cj_@01B_SIB
;------ if there no sib byte
	inc ecx
	movzx eax, ah
	shl eax, 2	; imul eax, eax, 4
	mov ebx, regz[eax]
	lodsb
	cbw
	cwde
	add ebx, eax
	invoke GetRealAddress, ebx
	inc ebx
	jz cj_modrm_1_bad_addr
	dec ebx
	mov dl, main_opcode
	mov cmdbuff[0], dl
	mov al, modrmb
	and al, 00111000b
	or al,  al
	mov cmdbuff[1], 00000101b
	mov dword ptr cmdbuff[2], ebx
	jmp emulate_it
;------ if there sib		
cj_@01B_SIB :
	lodsb
	movzx ebx, al
	and ebx, 00011100b
	shl ebx, 2
	mov ebx, regz[ebx]
	movzx edx, al
	and edx, 11100000b
	shl edx, 2
	mov edx, regz[edx]
	and al, 00000011b
	xchg eax, ecx
	shl edx, cl
	xchg eax, ecx
	add edx, ebx
	add ecx, 2
	lodsb
	cbw
	cwde
	add edx, eax
	invoke GetRealAddress, edx
	inc ebx
	jz cj_modrm_1_bad_addr
	dec ebx
	mov dl, main_opcode
	mov cmdbuff[0], dl
	mov al, modrmb
	and al, 00111000b
	or al,  00000101b
	mov byte ptr cmdbuff[1], al
	mov dword ptr cmdbuff[2], ebx
	jmp emulate_it
;############################# SPEC 8DH ##########################################################;
;------------------------------ lea cmd emulation ------------------------------------------------;
@8DH_modrm_1_bad_addr :
	xor eax, eax
	dec eax
	ret
spec_@8DH :
	mov main_opcode, al
	inc ecx
	;------- get length
	lodsb
@8DH_spec_2_modrmb_1 :
	mov modrmb, al
	mov bl, al		; bl will be mod
	and bl, 11000000b
	mov bh, al		; bh will be reg
	and bh, 00111000b
	mov ah, al
	and ah, 00000111b	; ah will be r/m
	;----- what mod ?
	cmp bl, 00000000b
	jnz @8DH_not_register_mode2
			test prefixfl, 0001000000000000b
			jnz @8DH_@67H
			;-------- 32 bit add mode calculations
				;----- are sib or imm addr
				cmp ah, 00000100b
				jz @8DH_sib_shit_1
				cmp ah, 00000101b
				jz @8DH_im32_1
				;------ if simply register
				xor edx, edx
				test prefixfl, 0000001000000000b
				jz @8DH_no_@00_simp_reg_66H
					mov byte ptr cmdbuff[0], 66H
					inc edx
			@8DH_no_@00_simp_reg_66H :
				movzx eax, ah
				shl eax, 2	; imul eax, eax, 4
				mov ebx, regz[eax]
				mov al, main_opcode
				mov cmdbuff[edx+0], al
				mov al, modrmb
				mov cmdbuff[edx+1], al
				mov dword ptr cmdbuff[edx+2], ebx
				jmp emulate_it
				;------ if there sib
			@8DH_sib_shit_1 :
				inc ecx
				push ecx
				xor eax, eax
				lodsb
				movzx ebx, al
				and ebx, 00111000b
				shr ebx, 1
				mov ebx, regz[ebx]
				mov cl, al
				and cl, 11000000b
				shl ebx, cl
				pop ecx
				movzx edx, al
				and edx, 00000111b
				shl edx, 2
				mov edx, regz[edx]
				add ebx, edx
				xor edx, edx
				test prefixfl, 0000001000000000b
				jz @8DH_not_@00_sib_66H
					mov byte ptr [edx], 66H
					inc edx
			@8DH_not_@00_sib_66H :
				mov al, main_opcode
				mov cmdbuff[edx+0], al
				mov al, modrmb
				and al, 00111000b
				or al,  00000101b
				mov cmdbuff[edx+1], al
				mov dword ptr cmdbuff[edx+2], ebx
				jmp emulate_it
				;------ if im32
			@8DH_im32_1 	 :
				add ecx, 4
				lodsd
				jz @8DH_modrm_1_bad_addr
				dec ebx
				test prefixfl, 0000001000000000b
				jnz @8DH_im32_1_66H_prefx
					mov dl, main_opcode
					mov cmdbuff[0], dl
					mov dl, modrmb
					mov cmdbuff[1], dl
					mov dword ptr cmdbuff[2], ebx
					jmp emulate_it
				@8DH_im32_1_66H_prefx :
					mov dl, main_opcode
					mov cmdbuff[0], 66H
					mov cmdbuff[1], dl
					mov dl, modrmb
					mov cmdbuff[2], dl
					mov dword ptr cmdbuff[3], ebx
					jmp emulate_it
		;-------- 16 bit mode calculations
		@8DH_@67H :
			xor eax, eax		; don't suported yet
			dec eax
			ret
	
@8DH_not_register_mode2 :
;------------- are there simply registers ?
	cmp bl, 11000000b
	jnz @8DH_not_register_mode
		xor edx, edx
		test prefixfl, 0000001000000000b
		jz @8DH_@not_11H_66H
			mov cmdbuff[edx], 66H
			inc edx
	@8DH_@not_11H_66H :
		mov al, main_opcode
		mov cmdbuff[edx], al
		mov al, modrmb
		mov cmdbuff[edx+1], al
		jmp emulate_it
@8DH_not_register_mode :
;------------ are there off32( mod = 2) ?
	cmp bl, 10000000b
	jnz @8DH_not_10B
		cmp ah, 00000101b
		jz @8DH_@10B_SIB
		add ecx, 4
	;------ all right. there no sib
		movzx ebx, ah
		shl ebx, 2
		lodsd
		mov ebx, regz[ebx]
		add ebx, eax
			xor edx, edx
			test prefixfl, 0000001000000000b
			jz @8DH_@not_10_66H
				mov cmdbuff[edx], 66H
				inc edx
		@8DH_@not_10_66H :
			mov al, main_opcode
			mov cmdbuff[edx+0], al
			mov al, modrmb
			and al, 00111000b
			or al,  00000101b
			mov cmdbuff[edx+1], al
			mov dword ptr cmdbuff[2], ebx
			jmp emulate_it
			;---- byte
	;------ shit. There SIB byte
	@8DH_@10B_SIB :
		lodsb
		movzx ebx, al
		and ebx, 00011100b
		shl ebx, 2
		mov ebx, regz[ebx]
		movzx edx, al
		and edx, 11100000b
		shl edx, 2
		mov edx, regz[edx]
		and al, 00000011b
		xchg eax, ecx
		shl edx, cl
		xchg eax, ecx
		add edx, ebx
		add ecx, 5
		lodsd
		add edx, eax
		xor edx, edx
		test prefixfl, 0000001000000000b
		jz @8DH_@10B_SIB_NO_66H
			mov cmdbuff[edx], 66H
			inc edx
	@8DH_@10B_SIB_NO_66H :
		mov al, main_opcode
		mov cmdbuff[edx+0], al
		mov al, modrmb
		and al, 00111000b
		or al,  00000101b
		mov cmdbuff[edx+1], al
		mov dword ptr cmdbuff[edx+2], ebx
		jmp emulate_it
@8DH_not_10B :
;---------- yeah. It is of course simple off8
	cmp ah, 00000101b
	jz @8DH_@01B_SIB
;------ if there no sib byte
	inc ecx
	movzx eax, ah
	shl eax, 2	; imul eax, eax, 4
	mov ebx, regz[eax]
	lodsb
	cbw
	cwde
	add ebx, eax
	xor edx, edx
	test prefixfl, 0000001000000000b
	jz @8DH_@10B_no_66H
		mov cmdbuff[edx], 66H
		inc edx
@8DH_@10B_no_66H :
	mov al, main_opcode
	mov cmdbuff[edx+0], al
	mov al, modrmb
	and al, 00111000b
	or al,  00000101b
	mov cmdbuff[edx+1], al
	mov dword ptr cmdbuff[edx+2], ebx
	jmp emulate_it
;------ if there sib		
@8DH_@01B_SIB :
	lodsb
	movzx ebx, al
	and ebx, 00011100b
	shl ebx, 2
	mov ebx, regz[ebx]
	movzx edx, al
	and edx, 11100000b
	shl edx, 2
	mov edx, regz[edx]
	and al, 00000011b
	xchg eax, ecx
	shl edx, cl
	xchg eax, ecx
	add edx, ebx
	add ecx, 2
	lodsb
	cbw
	cwde
	add edx, eax
	xor edx, edx
	test prefixfl, 0000001000000000b
	jz @01_no_66H
		mov cmdbuff[edx], 66H
		inc edx
@8DH_@01_no_66H : 
	mov al, main_opcode
	mov cmdbuff[edx+0], al
	mov byte ptr cmdbuff[edx+1], 00000101b
	mov dword ptr cmdbuff[edx+2], ebx
	jmp emulate_it
;############################# SPEC 8EH ##########################################################;
spec_@8EH :
	mov main_opcode, al
	inc ecx
	;------- get length
	lodsb
	mov modrmb, al
	mov bl, al		; bl will be mod
	and bl, 11000000b
	mov bh, al		; bh will be reg
	and bh, 00111000b
	mov ah, al
	and ah, 00000111b	; ah will be r/m
	;----- what mod ?
	cmp bl, 00000000b
	jnz @8EH_not_register_mode2
			test prefixfl, 0001000000000000b
			jnz @67H
			;-------- 32 bit add mode calculations
				;----- are sib or imm addr
				cmp ah, 00000100b
				jz @8EH_sib_shit_1
				cmp ah, 00000101b
				jz @8EH_im32_1
				;------ if simply register
				cmp ah, 028H		; 00101000b
				ja @8EH_emulation_failure_0
				;----- are there sregs that can be simply emulated ?
				dec esi
				cmp ah, 28H
				jz modrm_1
				inc esi 
				;------ no. Need additional control
				movzx eax, ah
				shl eax, 2	; imul eax, eax, 4
				mov ebx, regz[eax]
				invoke GetRealAddress, ebx	; rl addr in ebx
				inc ebx
				jnz @8EH_emulation_ok_0
				@8EH_emulation_failure_0 :
					xor eax, eax
					dec eax
					ret
			@8EH_emulation_ok_0 :
				dec ebx
				;mov regz[eax], ebx
				mov dl, main_opcode
				mov cmdbuff[0], dl
				mov dl, modrmb
				and dl, 00111000b
				or dl,  00000101b
				mov cmdbuff[1], dl
				mov dword ptr cmdbuff[2], ebx
				mov ax, word ptr [ebx]
				mov dx, cs
				cmp ax, dx
				jz @8EH_00_can_continue
				mov dx, ds
				cmp ax, dx
				jz @8EH_00_can_continue
				mov dx, ss
				cmp ax, dx
				jz @8EH_00_can_continue
				jmp @8EH_emulation_failure_0
			@8EH_00_can_continue :
				jmp emulate_it
				;------ if there sib
			@8EH_sib_shit_1 :
				inc ecx
				xor eax, eax
				lodsb
				movzx ebx, al
				and ebx, 00011100b
				shl ebx, 2
				mov ebx, regz[ebx]
				movzx edx, al
				and edx, 11100000b
				shl edx, 2
				mov edx, regz[edx]
				and al, 00000011b
				xchg eax, ecx
				shl edx, cl
				xchg eax, ecx
				add ebx, edx
				invoke GetRealAddress, ebx	; rl addr in ebx
				mov dl, main_opcode
				mov cmdbuff[0], dl
				mov dl, modrmb
				and dl, 00111000b
				or dl,  00000101b
				mov cmdbuff[1], dl
				mov dword ptr cmdbuff[2], ebx
				mov ax, word ptr [ebx]
				mov dx, cs
				cmp ax, dx
				jz @8EH_00_can_continue
				mov dx, ds
				cmp ax, dx
				jz @8EH_00_can_continue
				mov dx, ss
				cmp ax, dx
				jz @8EH_00_can_continue
				jmp @8EH_emulation_failure_0
				jmp emulate_it
				;------ if im32
			@8EH_im32_1 	 :
				add ecx, 4
				lodsd
				invoke GetRealAddress, eax
				inc ebx
				jnz @8EH_im32_1_ok
					xor eax, eax
					dec eax
					ret
			@8EH_im32_1_ok :
				dec ebx
				test prefixfl, 0000001000000000b
				jnz @8EH_im32_1_66H_prefx
					mov dl, main_opcode
					mov cmdbuff[0], dl
					mov dl, modrmb
					mov cmdbuff[1], dl
					mov dword ptr cmdbuff[2], ebx
					mov ax, word ptr [ebx]
					mov dx, cs
					cmp ax, dx
					jz @8EH_00_can_continue
					mov dx, ds
					cmp ax, dx
					jz @8EH_00_can_continue
					mov dx, ss
					cmp ax, dx
					jz @8EH_00_can_continue
					jmp @8EH_emulation_failure_0
					jmp emulate_it
				@8EH_im32_1_66H_prefx :
					mov dl, main_opcode
					mov cmdbuff[0], 66H
					mov cmdbuff[1], dl
					mov dl, modrmb
					mov cmdbuff[2], dl
					mov dword ptr cmdbuff[3], ebx
					mov ax, word ptr [ebx]
					mov dx, cs
					cmp ax, dx
					jz @8EH_00_can_continue
					mov dx, ds
					cmp ax, dx
					jz @8EH_00_can_continue
					mov dx, ss
					cmp ax, dx
					jz @8EH_00_can_continue
					jmp @8EH_emulation_failure_0
					jmp emulate_it
				
		;-------- 16 bit mode calculations
		@8EH_@67H :
			xor eax, eax		; don't suported yet
			dec eax
			ret
			
		
		
@8EH_not_register_mode2 :
;------------- are there simply registers ?
	cmp bl, 11000000b
	jnz @8EH_not_register_mode
		mov dl, main_opcode
		mov cmdbuff[0], dl
		mov dl, modrmb
		mov cmdbuff[1], dl
		;------- add control with sregs
		movzx ebx, bh
		mov eax, dword ptr regz[ebx]
		mov dx, cs
		cmp ax, dx
		jz @8EH_00_can_continue
		mov dx, ds
		cmp ax, dx
		jz @8EH_00_can_continue
		mov dx, ss
		cmp ax, dx
		jz @8EH_00_can_continue
		jmp @8EH_emulation_failure_0
		jmp emulate_it
@8EH_not_register_mode :
;------------ are there off32( mod = 2) ?
	cmp bl, 10000000b
	jnz not_10B
		test ah, 00000101b
		jnz @8EH_@10B_SIB
		add ecx, 4
	;------ all right. there no sib
		movzx ebx, ah
		shl ebx, 2
		lodsd
		mov ebx, regz[ebx]
		add ebx, eax
		invoke GetRealAddress, ebx
		inc ebx
		jz @8EH_modrm_1_bad_addr
		dec ebx
			mov dl, main_opcode
			mov cmdbuff[0], dl
			mov dl, modrmb
			and dl, 00111000b
			or dl,  00000101b
			mov cmdbuff[1], dl
			mov dword ptr cmdbuff[2], ebx
				;---- check
				mov ax, word ptr [ebx]
				mov dx, cs
				cmp ax, dx
				jz @8EH_00_can_continue
				mov dx, ds
				cmp ax, dx	
				jz @8EH_00_can_continue
				mov dx, ss
				cmp ax, dx
				jz @8EH_00_can_continue
				jmp @8EH_emulation_failure_0
			jmp emulate_it
	@8EH_modrm_1_bad_addr :
		xor eax, eax
		dec eax
		ret
	;------ shit. There SIB byte
	@8EH_@10B_SIB :
		lodsb
		movzx ebx, al
		and ebx, 00011100b
		shl ebx, 2
		mov ebx, regz[ebx]
		movzx edx, al
		and edx, 11100000b
		shl edx, 2
		mov edx, regz[edx]
		and al, 00000011b
		xchg eax, ecx
		shl edx, cl
		xchg eax, ecx
		add edx, ebx
		add ecx, 5
		lodsd
		add edx, eax
		invoke GetRealAddress, edx
		inc ebx
		jz @8EH_modrm_1_bad_addr
		dec ebx
		mov dl, main_opcode
		mov cmdbuff[0], dl
		mov dl, modrmb
		and dl, 00111000b
		or dl,  00000101b
		mov cmdbuff[1], dl
		mov dword ptr cmdbuff[2], ebx
		;---- check
				mov ax, word ptr [ebx]
				mov dx, cs
				cmp ax, dx
				jz @8EH_00_can_continue
				mov dx, ds
				cmp ax, dx	
				jz @8EH_00_can_continue
				mov dx, ss
				cmp ax, dx
				jz @8EH_00_can_continue
				jmp @8EH_emulation_failure_0
		jmp emulate_it
@8EH_not_10B :
;---------- yeah. It is of course simple off8
	test ah, 00000101b
	jnz @01B_SIB
;------ if there no sib byte
	inc ecx
	movzx eax, ah
	shl eax, 2	; imul eax, eax, 4
	mov ebx, regz[eax]
	lodsb
	cbw
	cwde
	add ebx, eax
	invoke GetRealAddress, ebx
	inc ebx
	jz @8EH_modrm_1_bad_addr
	dec ebx
	mov dl, main_opcode
	mov cmdbuff[0], dl
	mov dl, modrmb
	and dl, 00111000b
	or dl,  00000101b
	mov cmdbuff[1], dl
	mov dword ptr cmdbuff[2], ebx
	;---- check
				mov ax, word ptr [ebx]
				mov dx, cs
				cmp ax, dx
				jz @8EH_00_can_continue
				mov dx, ds
				cmp ax, dx	
				jz @8EH_00_can_continue
				mov dx, ss
				cmp ax, dx
				jz @8EH_00_can_continue
				jmp @8EH_emulation_failure_0
	jmp emulate_it
;------ if there sib		
@8EH_@01B_SIB :
	lodsb
	movzx ebx, al
	and ebx, 00011100b
	shl ebx, 2
	mov ebx, regz[ebx]
	movzx edx, al
	and edx, 11100000b
	shl edx, 2
	mov edx, regz[edx]
	and al, 00000011b
	xchg eax, ecx
	shl edx, cl
	xchg eax, ecx
	add edx, ebx
	add ecx, 2
	lodsb
	cbw
	cwde
	add edx, eax
	invoke GetRealAddress, edx
	inc ebx
	jz @8EH_modrm_1_bad_addr
	dec ebx
	mov dl, main_opcode
	mov cmdbuff[0], dl
	mov dl, modrmb
	and dl, 00111000b
	or dl,  00000101b
	mov byte ptr cmdbuff[1], dl
	mov dword ptr cmdbuff[2], ebx
	;---- check
				mov ax, word ptr [ebx]
				mov dx, cs
				cmp ax, dx
				jz @8EH_00_can_continue
				mov dx, ds
				cmp ax, dx	
				jz @8EH_00_can_continue
				mov dx, ss
				cmp ax, dx
				jz @8EH_00_can_continue
				jmp @8EH_emulation_failure_0
	jmp emulate_it

;############################# @0D7H - XLAT emulation ############################################;
@0D7H :
	sub ebx, inh.OptionalHeader.ImageBase
	jc @0D7H_invalid_addr
	add ebx, 256
	cmp ebx, inh.OptionalHeader.SizeOfImage
	ja @0D7H_invalid_addr
	sub ebx, 256
	add ebx, pRealPE
	mov cmdbuff[0], 0D7H
	jmp emulate_it
	@0D7H_invalid_addr :
	xor eax, eax
	dec eax
	ret
;############################# STRING INST #######################################################;
@0A4H :
@0A5H :
@0A6H :
@0A7H :
	mov edx, 3
	jmp string_inst
@0AAH :
@0ABH :
@0AEH :
@0AFH :
	mov edx, 2

	jmp string_inst
@0ACH :
@0ADH :
	mov edx, 1
	;jmp string_inst
;=========================== main emulator for strings ===================================;
string_inst :
	mov main_opcode, al
;--------- are there prefixes ?
	mov byte ptr string_cmd_buff_1[0], al
	mov word ptr string_cmd_buff_2[0], 9090H
	test prefixfl, 0000000000000010b
	jnz repne_prfx
	test prefixfl, 0000000000000100b
	jnz repz_prfx
init_str_emul :
	push flagz
	popfd
	xchg eax, regz[0]
	xchg ecx, regz[4]
	xchg esi, regz[24]
	xchg edi, regz[28]
;---------- main_loop
	main_str_loop :
		pushfd
		pushfd
		pop flagz
		test edx, 00000001b	; are esi used ?
		jz esi_not_used
		mov ebx, esi
		sub ebx, inh.OptionalHeader.ImageBase
		jc str_addr_error
		cmp ebx, inh.OptionalHeader.SizeOfImage
		jae str_addr_error
		add ebx, pRealPE
		mov esi, ebx
	esi_not_used :
		test edx, 00000010b
		jz edi_not_used
		mov ebx, edi
		sub ebx, inh.OptionalHeader.ImageBase
		jc str_addr_error
		cmp ebx, inh.OptionalHeader.SizeOfImage
		ja str_addr_error
		add ebx, pRealPE
		mov edi, ebx
	edi_not_used :
		popfd
		string_cmd_buff_1 DB 1 dup (90H)
		pushfd
		test edx, 00000001b
		jz esi_not_used_2
		sub esi, pRealPE
		add esi, inh.OptionalHeader.ImageBase
	esi_not_used_2 :
		test edx, 00000010b
		jz edi_not_used_2
		sub edi, pRealPE
		add edi, inh.OptionalHeader.ImageBase
	edi_not_used_2 :
		popfd
		test prefixfl, 0000000000000110b
		jz end_str_inst
		test flagz, 1024
		jnz df_active
		inc ecx
		jmp after_df_check
	df_active :
		dec ecx
	after_df_check :
		string_cmd_buff_2 DB 5 dup (90H)
;--------- restore all
end_str_inst :
	pushfd
	pop flagz
	xchg eax, regz[0]
	xchg ecx, regz[4]
	xchg esi, regz[24]
	xchg edi, regz[28]
	add cur_eip, ecx
	mov eax, ecx
	ret
;---------- repnz prefix
repne_prfx :
	mov word ptr string_cmd_buff_2[0],  840FH		 	;!!!!!!!!!!!!!!!! optimizate this fucked code !!!!!!!!!!!!!!!!!!!!
	mov dword ptr string_cmd_buff_2[2],  offset main_str_loop - offset string_cmd_buff_2 - 6 
	jmp init_str_emul
;---------- repz refix
repz_prfx :				;!!!!!!!!!!!!!!!! optimizate this fucked code !!!!!!!!!!!!!!!!!!!!
	mov word ptr string_cmd_buff_2[0],  850FH		 	;!!!!!!!!!!!!!!!! optimizate this fucked code !!!!!!!!!!!!!!!!!!!!
	mov dword ptr string_cmd_buff_2[2],  offset main_str_loop - offset string_cmd_buff_2 - 6
	jmp init_str_emul
;---------- error in address
str_addr_error :
					pop eax	; added | AHTUNG BLA
	xor eax, eax
	dec eax
	ret
;############################ SPEC oFeH ##########################################################;
spec_0FEH :
	mov bl, al
	and bl, 00111000b
	cmp bl, 8H
	ja EmulateCmd_UnknowInstr
	mov are_3_ops, 1
	jmp modrm_1
;############################# spec C1, C0 ###################################################;
spec_0C1H :
spec_0C0H :
spec_80H :
spec_82H :
spec_83H :
	mov are_3_ops, 1
	jmp modrm_1
;############################## SPEC 81H #################################################;
spec_81H :
	mov are_3_ops, 2
	jmp modrm_1
;############################# spec @0F6H,0F7H ###########################################;


spec_@0F6H :
	mov bl, al
	and bl, 00111000b
	jnz modrm_1
	mov are_3_ops, 1
	jmp modrm_1
spec_@0F7H :
	mov bl, al
	and bl, 00111000b
	jnz modrm_1
	mov are_3_ops, 2
	jmp modrm_1
	
;############################# RETN EMUL 0C2H #######################################;
retN_emul_0C2H :
	;----- are there 66H prefix ?
	test prefixfl, 0000001000000000b		; if there this shit all will be bad =(
	jnz EmulateCmd_TotalError
	xor eax, eax
	lodsw
	;----- no, all right
	xchg esp, regz[16]
	pop edx
	xchg esp, regz[16]
	invoke GetRealAddress, edx
	mov need_av_check, 0
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov cur_eip, ebx
	add regz[16], eax
	mov eax, ecx
	ret
	
;############################# RETN EMUL 0C3H ########################################;
retN_emul_0C3H :
;-------- are there fucked 66h prefix ?
	test prefixfl, 0000001000000000b		; if there this shit all will be bad =(
	jnz EmulateCmd_TotalError
;-------- no. contnue
	xchg regz[16], esp
	pop eax
	xchg regz[16], esp
	invoke GetRealAddress, eax
	mov need_av_check, 0
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov cur_eip, ebx
	mov eax, ecx
	ret

;############################# rel calln emul ########################################;
rel_calln_emul :
	mov main_opcode, al
	test prefixfl, 0000001000000000b
	jnz rel_call_emul_66H_prefx
	add ecx, 4
	lodsd
	add eax, cur_eip
	add eax, ecx
	sub eax, pRealPE
	add eax, inh.OptionalHeader.ImageBase
	invoke GetRealAddress, eax
	mov need_av_check, 0
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov cur_eip, ebx
	xchg regz[16], esp
	push eax
	xchg regz[16], esp
	mov cur_eip, ebx
	mov eax, ecx
	ret
rel_call_emul_66H_prefx :
	lodsw
	add ecx, 2
	movsx eax, ax
	add eax, cur_eip
	add eax, ecx
	sub eax, pRealPE
	add eax, inh.OptionalHeader.ImageBase
	invoke GetRealAddress, eax
	mov need_av_check, 0
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	xchg regz[16], esp
	push eax
	xchg regz[16], esp
	mov cur_eip, ebx
	mov eax, ecx
	ret
;############################# rel jmpn emul ########################################;
rel_jmpn_emul :
	mov main_opcode, al
	test prefixfl, 0000001000000000b
	jnz rel_jmp_emul_66H_prefx
	add ecx, 4
	lodsd
	add eax, cur_eip
	add eax, ecx
	mov ebx, pRealPE
	cmp eax, ebx
	jb EmulateCmd_TotalError
	add ebx, inh.OptionalHeader.SizeOfImage
	cmp eax, ebx
	jae EmulateCmd_TotalError
		;invoke GetRealAddress, eax
		;inc ebx
		;jz EmulateCmd_TotalError
		;dec ebx
		;mov cur_eip, ebx
	mov cur_eip, eax
	mov eax, ecx
	ret
rel_jmp_emul_66H_prefx :
	lodsw
	add ecx, 2
	movsx eax, ax
	add eax, cur_eip
	add eax, ecx
	invoke GetRealAddress, eax
	mov need_av_check, 0
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov cur_eip, ebx
	mov eax, ecx
	ret
	
;############################ DIR IA 32 ADDR ###################################;
dir_ia_32_addr :
	mov main_opcode, al
	test prefixfl, 0000010000000000b
	jnz dir_ia_32_addr_67H
	add ecx, 4
	lodsd
	invoke GetRealAddress, eax
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov dl, main_opcode
	mov cmdbuff[0], dl
	mov dword ptr cmdbuff[1], ebx
	
	jmp emulate_it
dir_ia_32_addr_67H :
	add ecx, 2
	xor eax, eax
	lodsw
	invoke GetRealAddress, eax
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov dl, main_opcode
	mov cmdbuff[0], 67H
	mov cmdbuff[1], dl
	mov word ptr cmdbuff[2], bx
	jmp emulate_it
;############################ JXX CMD ##########################################;
jxx_cmd :
	inc ecx
	mov main_opcode, al
	mov jxx_jump_or_no[0], al
	push flagz
	popfd
	xchg ecx, regz[4]
jxx_jump_or_no DB 70H, 02H
	jmp no_jump
	xchg ecx, regz[4]
	lodsb
	movsx eax, al
	add eax, ecx
	mov ebx, cur_eip
	sub ebx, pRealPE
	add ebx, inh.OptionalHeader.ImageBase
	add ebx, eax
	invoke GetRealAddress, ebx
	mov need_av_check, 0
	inc ebx
	jz EmulateCmd_TotalError
	dec ebx
	mov cur_eip, ebx
	mov eax, ecx
	ret
no_jump :
	xchg ecx, regz[4]
	add cur_eip, ecx
	mov eax, ecx
	ret
;############################ SIMPLY CMD im8 ###################################;
simply_command_2_im8 :
	mov dl, al
	mov cmdbuff[0], dl
	inc ecx
	lodsb
	mov cmdbuff[1], al
	jmp emulate_it
;############################ SIMPLY CMD im32 ###################################;
simply_command_2_im32 :
	test prefixfl, 0000001000000000b
	jz simply_command_im32_not66H
	;------- if fucked 66H prefix
	mov cmdbuff[1], al
	lodsw
	add ecx, 2
	mov cmdbuff[0], 66H
	mov word ptr cmdbuff[2], ax
	jmp emulate_it
	;------- if not fucked 66H prefix =)
simply_command_im32_not66H :
	mov cmdbuff[0], al
	lodsd
	add ecx, 4
	mov dword ptr cmdbuff[1], eax
	jmp emulate_it
	
;############################ STACK COMMAND AND SIMPLY COMMANDS(1 byte) ######################;

stack_command :
	mov need_av_check, 1
	mov edx, regz[16]
	mov last_addr, edx
	mov edx, [edx]
	mov dword ptr OldData[0], edx
simply_command :
	mov main_opcode, al
	xor eax, eax
	test prefixfl, 0000001000000000b
	jz stack_cmd_not_66H_pref
		mov cmdbuff[eax], 066H
		inc eax
stack_cmd_not_66H_pref :
	mov dl, main_opcode
	mov cmdbuff[eax], dl
	jmp emulate_it
;############################ PREFIX ############################;
;67H, 66H, 65H, 64H, 26H, 3EH, 36H, 2EH, F3H, F2H, F0H
prefix_0F0H :
	or prefixfl, 0000000000000001b
	jmp repeat_decode
prefix_0F2H :
	or prefixfl, 0000000000000010b
	jmp repeat_decode
prefix_0F3H :
	or prefixfl, 0000000000000100b
	jmp repeat_decode
prefix_02EH :
	or prefixfl, 0000000000001000b
	jmp repeat_decode
prefix_036H :
	or prefixfl, 0000000000010000b
	jmp repeat_decode
prefix_03EH :
	or prefixfl, 0000000000100000b
	jmp repeat_decode
prefix_026H :
	or prefixfl, 0000000001000000b
	jmp repeat_decode
prefix_064H :
	or prefixfl, 0000000010000000b
	jmp repeat_decode
prefix_065H :
	or prefixfl, 0000000100000000b
	jmp repeat_decode
prefix_066H :
	or prefixfl, 0000001000000000b
	jmp repeat_decode
prefix_067H :
	or prefixfl, 0000010000000000b
	jmp repeat_decode



;############################ MOD_RM ############################;
modrm_1_bad_addr :
	xor eax, eax
	dec eax
	ret
modrm_1 :
	mov main_opcode, al
	inc ecx
	;------- get length
	lodsb
spec_2_modrmb_1 :
	mov modrmb, al
	mov bl, al		; bl will be mod
	and bl, 11000000b
	mov bh, al		; bh will be reg
	and bh, 00111000b
	mov ah, al
	and ah, 00000111b	; ah will be r/m
	;----- what mod ?
	cmp bl, 00000000b
	jnz not_register_mode2
			test prefixfl, 0001000000000000b
			jnz @67H
			;-------- 32 bit add mode calculations
				;----- are sib or imm addr
				cmp ah, 00000100b
				jz sib_shit_1
				cmp ah, 00000101b
				jz im32_1
				;------ if simply register
				xor edx, edx
				test prefixfl, 0000001000000000b
				jz no_@00_simp_reg_66H
					mov byte ptr cmdbuff[0], 66H
					inc edx
			no_@00_simp_reg_66H :
				movzx eax, ah
				shl eax, 2	; imul eax, eax, 4
				mov ebx, regz[eax]
				invoke GetRealAddress, ebx	; rl addr in ebx
				inc ebx
				jz modrm_1_bad_addr
				dec ebx
				mov al, main_opcode
				mov cmdbuff[edx+0], al
				mov al, modrmb
				and al, 00111000b
				or al,  00000101b
				mov cmdbuff[edx+1], al
				mov dword ptr cmdbuff[edx+2], ebx
				cmp are_3_ops, 00000001b
				jz @00_3_ops_byte
				cmp are_3_ops, 00000010b
				jz @00_3_ops_dword
				jmp emulate_it
			;---- if special cmd with 1 byte op
			@00_3_ops_byte :
					lodsb
					inc ecx
					mov cmdbuff[edx+6], al
					jmp emulate_it
			;----- if special cmd with dword op
			@00_3_ops_dword :
				;------ are there 66h prefix
				;------ no
					test prefixfl, 0000001000000000b
					jnz  @00_3_ops_dword_66H
						lodsd
						add ecx, 4
						mov dword ptr cmdbuff[edx+6], eax
						jmp emulate_it
				;------- yes
				@00_3_ops_dword_66H :
						lodsw
						add ecx, 2
						mov word ptr cmdbuff[edx+6], ax
						jmp emulate_it
					
				;------ if there sib
			sib_shit_1 :
				inc ecx
				push ecx
				xor eax, eax
				lodsb
				movzx ebx, al
				and ebx, 00111000b
				shr ebx, 1
				mov ebx, regz[ebx]
				mov cl, al
				and cl, 11000000b
				shl ebx, cl
				pop ecx
				movzx edx, al
				and edx, 00000111b
				shl edx, 2
				mov edx, regz[edx]
				add ebx, edx
				xor edx, edx
				invoke GetRealAddress, ebx	; rl addr in ebx
				inc ebx
				jz modrm_1_bad_addr
				xor edx, edx
				test prefixfl, 0000001000000000b
				jz not_@00_sib_66H
					mov byte ptr [edx], 66H
					inc edx
			not_@00_sib_66H :
				mov al, main_opcode
				mov cmdbuff[edx+0], al
				mov al, modrmb
				and al, 00111000b
				or al,  00000101b
				mov cmdbuff[edx+1], al
				mov dword ptr cmdbuff[edx+2], ebx
				cmp are_3_ops, 1
				jz @00_sib_3_ops_byte
				cmp are_3_ops, 2
				jz @00_sib_3_ops_dword
					jmp emulate_it
					;------ 3 ops byte
				@00_sib_3_ops_byte :
					lodsb
					inc ecx
					mov cmdbuff[edx+3], al
					jmp emulate_it
					;------ 3 ops dword
				@00_sib_3_ops_dword :
						;---- are there fucked 66H prefix ?
					test prefixfl, 0000001000000000b
					jnz @00_sib_3_ops_dword_66H
						lodsd
						add ecx, 4
						mov dword ptr cmdbuff[edx+6], eax
						jmp emulate_it
				@00_sib_3_ops_dword_66H :
						lodsw
						add ecx, 2
						mov word ptr cmdbuff[edx+6], ax
						jmp emulate_it
					
				;------ if im32
			im32_1 	 :
				add ecx, 4
				lodsd
				invoke GetRealAddress, eax
				inc ebx
				jz modrm_1_bad_addr
				dec ebx
				test prefixfl, 0000001000000000b
				jnz im32_1_66H_prefx
					mov dl, main_opcode
					mov cmdbuff[0], dl
					mov dl, modrmb
					mov cmdbuff[1], dl
					mov dword ptr cmdbuff[2], ebx
					cmp are_3_ops, 1
					jz @00_im32_3_ops_byte_no66H
					cmp are_3_ops, 2
					jz @00_im32_3_ops_dword_no66H
					jmp emulate_it
					@00_im32_3_ops_byte_no66H :
						lodsb
						inc ecx
						mov cmdbuff[6], al
						jmp emulate_it
					@00_im32_3_ops_dword_no66H :
						lodsd
						add ecx, 4
						mov dword ptr cmdbuff[6], eax
						jmp emulate_it
				im32_1_66H_prefx :
					mov dl, main_opcode
					mov cmdbuff[0], 66H
					mov cmdbuff[1], dl
					mov dl, modrmb
					mov cmdbuff[2], dl
					mov dword ptr cmdbuff[3], ebx
					cmp are_3_ops, 1
					jz @00_im3_3_opd_byte_66H
					cmp are_3_ops, 2
					jz @00_im3_3_opd_dword_66H
					jmp emulate_it
				@00_im3_3_opd_byte_66H :
						lodsb
						inc ecx
						mov  cmdbuff[7], al
						jmp emulate_it
				@00_im3_3_opd_dword_66H :
						lodsw
						add ecx, 2
						mov word ptr cmdbuff[7], ax
						jmp emulate_it
						
				
		;-------- 16 bit mode calculations
		@67H :
			xor eax, eax		; don't suported yet
			dec eax
			ret
			
		
		
not_register_mode2 :
;------------- are there simply registers ?
	cmp bl, 11000000b
	jnz not_register_mode
		xor edx, edx
		test prefixfl, 0000001000000000b
		jz @not_11H_66H
			mov cmdbuff[edx], 66H
			inc edx
	@not_11H_66H :
		mov al, main_opcode
		mov cmdbuff[edx], al
		mov al, modrmb
		mov cmdbuff[edx+1], al
		cmp are_3_ops, 1
		jz @11_3_ops_byte
		cmp are_3_ops, 2
		jz @11_3_ops_dword
		jmp emulate_it
		;----- byte 
		@11_3_ops_byte :
			lodsb
			inc ecx
			mov cmdbuff[edx+2], al
			jmp emulate_it
		;----- dword or word
		@11_3_ops_dword :
			test prefixfl, 0000001000000000b
			jnz @11_3_ops_dword_66H
				lodsd
				add ecx, 4
				mov dword ptr cmdbuff[edx+2], eax
				jmp emulate_it
		@11_3_ops_dword_66H :
				lodsw
				add ecx, 2
				mov word ptr cmdbuff[edx+2], ax
				jmp emulate_it
not_register_mode :
;------------ are there off32( mod = 2) ?
	cmp bl, 10000000b
	jnz not_10B
		cmp ah, 00000101b
		jz @10B_SIB
		add ecx, 4
	;------ all right. there no sib
		movzx ebx, ah
		shl ebx, 2
		lodsd
		mov ebx, regz[ebx]
		add ebx, eax
		invoke GetRealAddress, ebx
		inc ebx
		jz modrm_1_bad_addr
		dec ebx
			xor edx, edx
			test prefixfl, 0000001000000000b
			jz @not_10_66H
				mov cmdbuff[edx], 66H
				inc edx
		@not_10_66H :
			mov al, main_opcode
			mov cmdbuff[edx+0], al
			mov al, modrmb
			and al, 00111000b
			or al,  00000101b
			mov cmdbuff[edx+1], al
			mov dword ptr cmdbuff[2], ebx
			cmp are_3_ops, 1
			jz @10_3_ops_byte
			cmp are_3_ops, 2
			jz @10_3_ops_dword
			jmp emulate_it
			;---- byte
			@10_3_ops_byte :
				lodsb
				inc ecx
				mov cmdbuff[edx+6], al
				jmp emulate_it
			;---- dword
			@10_3_ops_dword :
				test prefixfl, 0000001000000000b
				jnz @10_3_ops_word
				lodsd
				add ecx, 4
				mov dword ptr cmdbuff[edx+6], eax
				jmp emulate_it
			;---- word
			@10_3_ops_word :
				lodsw
				add ecx, 2
				mov word ptr cmdbuff[edx+6], ax
				jmp emulate_it
	;------ shit. There SIB byte
	@10B_SIB :
		lodsb
		movzx ebx, al
		and ebx, 00000111b
		shl ebx, 2
		mov ebx, regz[ebx]
		movzx edx, al
		and edx, 00111000b
		shr edx, 1
		mov edx, regz[edx]
		and al, 11000000b
		xchg eax, ecx
		shl edx, cl
		xchg eax, ecx
		add edx, ebx
		add ecx, 5
		lodsd
		add edx, eax
		invoke GetRealAddress, edx
		inc ebx
		jz modrm_1_bad_addr
		dec ebx
		xor edx, edx
		test prefixfl, 0000001000000000b
		jz @10B_SIB_NO_66H
			mov cmdbuff[edx], 66H
			inc edx
	@10B_SIB_NO_66H :
		mov al, main_opcode
		mov cmdbuff[edx+0], al
		mov al, modrmb
		and al, 00111000b
		or al,  00000101b
		mov cmdbuff[edx+1], al
		mov dword ptr cmdbuff[edx+2], ebx
		cmp are_3_ops, 1
		jz @10_sib_3_ops_byte
		cmp are_3_ops, 2
		jz @10_sib_3_ops_dword
		jmp emulate_it
		;---- byte 
		@10_sib_3_ops_byte :
			lodsb
			inc ecx
			mov cmdbuff[edx+6], al
			jmp emulate_it
		;---- dword
		@10_sib_3_ops_dword :
			test prefixfl, 0000001000000000b
			jnz @10_sib_3_ops_word
			lodsd
			add ecx, 4
			mov dword ptr cmdbuff[edx+6], eax
			jmp emulate_it
		;---- word
		@10_sib_3_ops_word :
			lodsw
			add ecx, 2
			mov dword ptr cmdbuff[edx+6], eax
			jmp emulate_it		
not_10B :
;---------- yeah. It is of course simple off8
	cmp ah, 00000101b
	jz @01B_SIB
;------ if there no sib byte
	inc ecx
	movzx eax, ah
	shl eax, 2	; imul eax, eax, 4
	mov ebx, regz[eax]
	lodsb
	cbw
	cwde
	add ebx, eax
	invoke GetRealAddress, ebx
	inc ebx
	jz modrm_1_bad_addr
	dec ebx
	xor edx, edx
	test prefixfl, 0000001000000000b
	jz @10B_no_66H
		mov cmdbuff[edx], 66H
		inc edx
@10B_no_66H :
	
	mov al, main_opcode
	mov cmdbuff[edx+0], al
	mov al, modrmb
	and al, 00111000b
	or al,  00000101b
	mov cmdbuff[edx+1], al
	mov dword ptr cmdbuff[edx+2], ebx
	cmp are_3_ops, 1
	jz @01_3_ops_byte
	cmp are_3_ops, 2
	jz @01_3_ops_dword
	jmp emulate_it
	;----- if additional op byte
	@01_3_ops_byte :
		lodsb
		inc ecx
		mov byte ptr cmdbuff[edx+6], al
		jmp emulate_it
	;----- if additional op dword
	@01_3_ops_dword :
		test prefixfl, 0000001000000000b
		jnz @01_3_ops_word
		lodsd
		add ecx, 4
		mov dword ptr cmdbuff[edx+6], eax
		jmp emulate_it
	@01_3_ops_word :
		lodsw
		add ecx, 2
		mov dword ptr cmdbuff[edx+6], eax
		jmp emulate_it
;------ if there sib		
@01B_SIB :
	lodsb
	movzx ebx, al
	and ebx, 00000111b
	shl ebx, 2
	mov ebx, regz[ebx]
	movzx edx, al
	and edx, 00111000b
	shl edx, 2
	mov edx, regz[edx]
	and al, 11000000b
	xchg eax, ecx
	shl edx, cl
	xchg eax, ecx
	add edx, ebx
	add ecx, 2
	lodsb
	movsx eax, al
	add edx, eax
	invoke GetRealAddress, edx
	inc ebx
	jz modrm_1_bad_addr
	dec ebx
	xor edx, edx
	test prefixfl, 0000001000000000b
	jz @01_no_66H
		mov cmdbuff[edx], 66H
		inc edx
@01_no_66H : 
	mov al, main_opcode
	mov cmdbuff[edx+0], al
	mov al, modrmb
	and al, 00111000b
	or al,  00000101b
	mov byte ptr cmdbuff[edx+1], al
	mov dword ptr cmdbuff[edx+2], ebx
	cmp are_3_ops, 1
	jz @01_sib_3_ops_byte
	cmp are_3_ops, 2
	jz @01_sib_3_ops_dword
	jmp emulate_it
	;---- byte
	@01_sib_3_ops_byte :
		lodsb
		inc ecx
		mov byte ptr cmdbuff[edx+6], al
		jmp emulate_it
	;---- dword
	@01_sib_3_ops_dword :
		test prefixfl, 0000001000000000b
		jnz @01_sib_3_ops_word
		lodsd
		add ecx, 4
		mov dword ptr cmdbuff[6], eax
		jmp emulate_it
	@01_sib_3_ops_word :
		lodsw
		add ecx, 2
		mov word ptr cmdbuff[edx+6], ax
		;jmp emulate_it			; be carefull with this shit !

;################################### EMULATE IT ##############################;
emulate_it :
;-------------- emul cmd
	push flagz
	popfd
	xchg eax, regz[00]
	xchg ecx, regz[04]
	xchg edx, regz[08]
	xchg ebx, regz[12]
	xchg esp, regz[16]
	xchg ebp, regz[20]
	xchg esi, regz[24]
	xchg edi, regz[28]
	cmdbuff DB 16 dup(90H)
	xchg regz[00], eax
	xchg regz[04], ecx
	xchg regz[08], edx
	xchg regz[12], ebx
	xchg regz[16], esp
	xchg regz[20], ebp
	xchg regz[24], esi
	xchg regz[28], edi
	pushfd
	pop flagz
	xor eax, eax
	mov eax, ecx
	add cur_eip, ecx
	ret
EmulateCmd	ENDP


;=================================================== THE END =========================================;
END Start
