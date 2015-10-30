/****************************************************************
		Hunter - signature scanner
*****************************************************************
	Author	:	Netesoff Yurii aka DeHunter
	EMail	:	dehunter@inbox.ru
	ICQ	:	422259
	Site	:	dehunters_soft.drmist.ru
*****************************************************************/ 
#include <windows.h>
#include <shlobj.h>
#include <commctrl.h>
#include "resource.h"
#include "wfak_io_codes.h"
//========================= DEF ==========================//
typedef DWORD (*SCANPROC)(BYTE *pFiles,  DWORD nFilesCounter, BYTE *pExts, DWORD nExtCounter) ;
typedef BYTE (*ActProc)(BYTE *pcName, BYTE *pcVir) ;
typedef BYTE (*HealProc)(BYTE *cPath) ;
#define WFAKSRVNAME	"wfak_0x00"
#define WFAKBINPATH "\\wfak_0x00.sys"
//------------------------ program description
#define description_text "This program is antivirus scaner. It uses the emulation technology to detect polymorphic \
viruses. It can detect polymorphic viruses using wildcards also. You can add new virus signatures using a virus \
database editor. The program can't detect viruses in archives.It hasn't heuristic analyze. But I will add this all in next versions. This is the \
zero version(alfa). I will be glad you to sent me your comments and ideas about program.\r\n Thanks for using my program.\r\n\
             10.28.2005, Netesoff Yurii ( DeHunter )" 
//-----------------------------------------------
//========================= PROTO =============================//
LRESULT CALLBACK MWndProc( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) ;
BOOL CALLBACK ReportDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK ScanDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) ;
BOOL CALLBACK WaitDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) ;
BOOL CALLBACK SettingsDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK VDBEditDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK AboutDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK ExtAddDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI LoadVdbTrd(LPVOID lpParam);
BOOL CALLBACK AddSigDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT SigEdtProc( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam ) ;
inline BYTE FormReport(HANDLE hFile) ;
void	ScanTrd(DWORD p1) ;
void	WaitTrd(DWORD p1) ;
inline int LoadSettings(HWND hDlg) ;
inline int LoadExtensions(HWND hDlg) ;

//======================= GLOBAL VARIABLES ====================//
DWORD dwCur, dwBuffSize, dwSigSize ;
int i ;
WNDPROC	OriginSigEdtProc ;
LVITEM lvi ;
char statestr[256] ;
char helpbuff[256];
char pcLastVdbUpdate[256] ;
HANDLE hAdditionalHeap ;
HWND hWaitDlg ;
DWORD VDBSize, VDBCounter ;
HANDLE hLoadVdbTrd ;
DWORD trd_ret_val ;
struct WAITDLGPARAM_T
{
	HANDLE hThread ;
	char add_buff[256] ;
} wait_dlg_param ;

struct
{
	char name[50] ;
	byte type ;
	byte sig_size ;
	BYTE sig[256] ;
} VDBOldItem ;
struct sigstruct 
{
	char name[50] ;
	byte type ;
	byte sig_size ;
} **ppVDB, t_sig_struct ;
OPENFILENAME ofn ;
ActProc	ActionProc ;
HWND hWnd, hTabControl, hDlgs[5] ;
DWORD nRepICounter ;
HANDLE hMapFile ;
HANDLE hSetFile ;
HBITMAP hBitmap;
static union 
{
	DWORD rw ;
	DWORD nSel ;
};
struct istruct
{
	char path[256]  ;
	char result[256] ;
	BYTE action ;
} *pRepData ;
WNDCLASS wc ;
char HexAlf[16] = { '0', '1', '2' , '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
char tbuff[256] ;
HANDLE hVDBFile, hRepFile ;
HANDLE *pRepFile, *pEdt, *pMpb ; 
HWND hTargList, hRepLV, hVDBLV ;
HANDLE hScanTrd, hWaitTrd, *phEmulTrd ;
BYTE *pexts ;
HINSTANCE hInst ;
DWORD nECounter ;
char CName[] = "WolfscannerCls" ;
HMODULE hScanLib ;
char cWndName[] = ":: Wolf antivirus 0x0 :: - Hunter" ;
MSG Msg ;
RECT rect ;
LPNMHDR lpNMHDR ;
char buff[256*3] ;
BYTE IsScaning, IsPaused ;
struct setstruct
{
	char QPath[256] ;
	char EPath[256] ;
	BYTE ScanMode ;
	BYTE Action;
	BYTE ccAction ;
	BYTE AOI ;
	DWORD EmulTime ;
	DWORD CheckStep ;
} sstruct, tsstruct, defset = { ".\\quarantine\\",".\\scanner_exts.dat", 0x05, 0, 0, 1, 4000, 6 }  ;

//################################ MAIN ################################//
int WINAPI WinMain( HINSTANCE htInst, HINSTANCE hPrevInst, LPSTR CmdLine, int nCmdShow )
{
//--------are we already runned ?
	hWnd = FindWindow(0, (LPSTR)&cWndName) ;
	if( hWnd )
	{
		MessageBox(0, "Wolf are already working", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
		ShowWindow(hWnd, SW_SHOWDEFAULT) ;
		SetForegroundWindow(hWnd) ;
		return 0 ;
	}
//-------- launch wfak -----------//
	SC_HANDLE hScm, hSrv ;
	DWORD ServiceStatus ;
	ServiceStatus =  1 ; // 1 - launched, 0 - not launched
	HANDLE hDev ; 
	hScm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS ) ;
	if( hScm == 0 )
	{
		ServiceStatus =  0 ;
		MessageBox(0, "Can't launch Wolf antikiller	module(Can't open SCM( Probably you are not admin ) ) .", \
			(LPTSTR)&cWndName, MB_ICONWARNING) ;
	}
	DWORD status ;
	GetCurrentDirectory(sizeof(buff), (LPTSTR)(&buff[0]) );
	lstrcat( &(buff[0]), WFAKBINPATH ) ;
	hSrv = CreateService( hScm, WFAKSRVNAME, WFAKSRVNAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, \
						   SERVICE_ERROR_NORMAL, (LPTSTR)&(buff[0]), 0, 0, 0, 0, 0) ; 
	if( !hSrv )
	{
		rw = GetLastError() ;
		if( GetLastError() != ERROR_SERVICE_EXISTS )
		{
		wfak_exec_total_err :
			MessageBox(0, "Can't launch Wolf antikiller module( Can't create service ) ", (LPTSTR)&cWndName, MB_ICONWARNING ) ;
			ServiceStatus = 0 ;
			goto wfak_err_continue_exec ;
		}
		else
		{
			hSrv = OpenService( hScm, WFAKSRVNAME, GENERIC_ALL ) ;
			if( !hSrv )
				goto wfak_exec_total_err ;
			status = StartService( hSrv, 0, 0 ) ;
			if(!status)
			{
				if(GetLastError() != ERROR_SERVICE_ALREADY_RUNNING )
					goto wfak_cant_start ;
			}
			goto wfak_already_exists ;
		}
	}
	if( !StartService( hSrv, 0, 0 ) )
	{
	wfak_cant_start :
		ServiceStatus =  0 ;
		status = GetLastError() ;
		MessageBox(0, "Can't start Wolf anti killer service !", (LPTSTR)&cWndName, MB_ICONWARNING) ;
		CloseServiceHandle( hSrv ) ;
		CloseServiceHandle( hScm ) ;
		goto wfak_err_continue_exec ;
	}
wfak_already_exists :
	hDev = CreateFile( "\\\\.\\wfak", FILE_ALL_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, \
						FILE_ATTRIBUTE_NORMAL, 0) ;
	if( hDev == INVALID_HANDLE_VALUE )
	{
		ServiceStatus =  0 ;
		MessageBox(0, "Can't open Wolf anti killer device", (LPTSTR)&cWndName, MB_ICONWARNING) ;
		goto wfak_err_continue_exec ;
	}
	buff[0] = 0xFF ;
	status = GetCurrentProcessId() ;
	__asm
	{
		mov ebx, offset buff
		inc ebx
		mov eax, status
		mov dword ptr [ebx], eax
		mov status, eax
	}
	status = DeviceIoControl(hDev, IOCTL_ADDPROCESSID, &(buff[0]), 5, 0, 0, &rw, 0) ;
	if(!status)
	{
		MessageBox(0, "Error add pid to Wolf anti killer service table", (LPTSTR)&cWndName, MB_ICONWARNING) ;
		goto wfak_err_continue_exec ;
	}
	DeviceIoControl(hDev, IOCTL_SETAKHOOK, 0, 0, 0, 0, &rw, 0 ) ;
wfak_err_continue_exec  :
	status = GetLastError() ;
	CloseServiceHandle( hScm ) ;
	CloseServiceHandle( hSrv ) ;
	CloseHandle( hDev ) ;
//-------- init some varz and create main window
	nRepICounter = 0 ;
	IsScaning = 0 ;
	IsPaused = 0 ;
	InitCommonControls() ;
	hInst = htInst ;
	wc.cbClsExtra = 0 ;
	wc.cbWndExtra = 0 ;
	wc.hInstance = hInst ;
	wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH) ;
	wc.lpszClassName = CName ;
	wc.lpszMenuName = 0 ;
	wc.style = CS_HREDRAW | CS_VREDRAW ;
	wc.lpfnWndProc = MWndProc ;
	wc.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_MAINICON)) ;
	wc.hCursor = LoadCursor(0, IDC_ARROW) ;
	RegisterClass(&wc) ;
	hWnd = CreateWindow( (LPCSTR)&(CName[0]), (LPSTR)&cWndName,\
		WS_OVERLAPPEDWINDOW ^ WS_MAXIMIZEBOX ^ WS_THICKFRAME, CW_USEDEFAULT , CW_USEDEFAULT, 700, 500, 0, 0, hInst, 0 ) ;
	ShowWindow(hWnd, SW_SHOWNORMAL) ;
	UpdateWindow(hWnd) ;
//-------- main msg loop
	while( GetMessage(&Msg, 0, 0, 0) )
	{
		TranslateMessage(&Msg) ;
		DispatchMessage(&Msg) ;
	}
//------ are there lauched wfak ?
if(!ServiceStatus)
	return 0 ; 
//------ remove our process id from it
	hDev = CreateFile( "\\\\.\\wfak", FILE_ALL_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, \
						FILE_ATTRIBUTE_NORMAL, 0) ;
	if( !hDev ) 
	{
		MessageBox(0, "Can't remove process id from Wolf anti killer becouse can't open device", (LPTSTR)&cWndName, MB_ICONWARNING) ;
		return 0 ;
	}
	status = DeviceIoControl(hDev, IOCTL_GETPROCESSIDLIST, 0, 0, &(buff[0]), 129, &rw, 0) ;
	if(!status)
	{
	rem_pid_bad_irp_req :
		MessageBox(0, "Can't remove process id from  Wolf anti killer becouse irp request was incorrect", (LPTSTR)&cWndName, MB_ICONWARNING) ;
		CloseHandle( hDev ) ;
		return 0 ;
	}
	BYTE ix ; 
	status = GetCurrentProcessId() ;
	for( ix = 0 ; ix < buff[0]; ix++ )
	{
		if( status == *( ( (DWORD *)(&(buff[0])+1) )+ix ) )
		{
			status = DeviceIoControl( hDev, IOCTL_REMPROCESSID, &ix, 1, 0, 0, &rw, 0) ;
			if(!status)
				goto rem_pid_bad_irp_req ;
			break ;
		}
	}
	if( ix >= buff[0] )
			MessageBox(0, "Can't remove process id from  Wolf anti killer becouse probably is has already removed", (LPTSTR)&cWndName, MB_ICONWARNING) ;
	CloseHandle( hDev ) ;
//------ are it was the last pid ? If yes remove service
	if(buff[0]!=1)
		return 0 ;
//------- Stop and remove service
	hScm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS) ;
	if(!hScm)
	{
		MessageBox( 0 , "Can't stop  Wolf anti killer becouse can't open SCM", (LPTSTR)&cWndName, MB_ICONWARNING) ;
		return 0 ;
	}
	hSrv = OpenService( hScm, WFAKSRVNAME, SERVICE_ALL_ACCESS ) ;
	if(!hSrv)
	{
		MessageBox(0, "Can't stop  Wolf anti killer becouse can't open it", (LPTSTR)&cWndName, MB_ICONWARNING) ;
		CloseServiceHandle( hScm ) ;
		return 0 ; 
	}
	CloseServiceHandle(hScm) ;
	SERVICE_STATUS _ss ;
	if( !ControlService( hSrv, SERVICE_CONTROL_STOP, &_ss ) )
	{
		MessageBox(0, "Can't stop  Wolf anti killer", (LPTSTR)&cWndName, MB_ICONWARNING) ;
		CloseServiceHandle( hSrv ) ;
		return 0 ;
	}
	if( !DeleteService( hSrv )  )
		MessageBox(0, "Can't delete  Wolf anti killer", (LPTSTR)&cWndName, MB_ICONWARNING) ;
	CloseServiceHandle( hSrv ) ;
//------- exit program
	return 0 ;
}

//################################ WNDPROC ################################//
LRESULT CALLBACK MWndProc( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) 
{
	
	TC_ITEM tcitem ;
	switch(uMsg)
	{
//##################### WM_CREATE
	case WM_CREATE :
		//-------- load fucked bitmap
		hBitmap =(HBITMAP) LoadBitmap(hInst, MAKEINTRESOURCE(IDB_LOGOBMP) ) ;
		//------- tab control
		hTabControl = CreateWindow(WC_TABCONTROL, 0, WS_VISIBLE | WS_TABSTOP | WS_CHILD |TCS_BUTTONS  |TCS_FLATBUTTONS  ,\
			50, 0, 640, 480, hWnd, 0,hInst, 0) ;
		tcitem.mask = TCIF_TEXT ;
		tcitem.pszText = " Scan" ;
		tcitem.iImage = -1 ;
		TabCtrl_InsertItem(hTabControl, 0, &tcitem) ;
		tcitem.pszText = "Report" ;
		TabCtrl_InsertItem(hTabControl, 1, &tcitem) ;
		tcitem.pszText = "Settings" ;
		TabCtrl_InsertItem(hTabControl, 2, &tcitem) ;
		tcitem.pszText = "VDB editor" ;
		TabCtrl_InsertItem(hTabControl, 3, &tcitem) ;
		tcitem.pszText = "About" ;
		TabCtrl_InsertItem(hTabControl, 4, &tcitem) ;
		//-------- create dialogz
		hDlgs[4] = CreateDialog(hInst, MAKEINTRESOURCE(IDD_ABOUTDLG), hTabControl, AboutDlgProc) ;
		hDlgs[3] = CreateDialog(hInst, MAKEINTRESOURCE(IDD_VDBEDITDLG), hTabControl, VDBEditDlgProc ) ;
		hDlgs[2] = CreateDialog(hInst, MAKEINTRESOURCE(IDD_SETTINGSDLG), hTabControl, SettingsDlgProc) ;
		hDlgs[1] = CreateDialog(hInst, MAKEINTRESOURCE(IDD_REPORTDLG), hTabControl, ReportDlgProc) ;
		hDlgs[0] = CreateDialog(hInst, MAKEINTRESOURCE(IDD_SCANDLG), hTabControl, ScanDlgProc) ;
		SetDlgItemText(hDlgs[0], IDC_SCANDLG_CURSCANEDT, "Waiting for command.") ;
		ShowWindow(hDlgs[0], SW_SHOWDEFAULT) ;
		ShowWindow(hDlgs[1], SW_HIDE) ;
		ShowWindow(hDlgs[2], SW_HIDE) ;
		ShowWindow(hDlgs[3], SW_HIDE) ;
		ShowWindow(hDlgs[4], SW_HIDE) ;
		//-------- list view ( Rep lv and VDB lv
		hRepLV = CreateWindow(WC_LISTVIEW, 0, WS_TABSTOP|WS_CHILD|WS_BORDER|WS_VISIBLE|LVS_AUTOARRANGE|LVS_REPORT |LVS_OWNERDATA ,
							 10, 10, 590, 365, hDlgs[1], 0, hInst, 0) ;
		hVDBLV = CreateWindow(WC_LISTVIEW, 0, WS_TABSTOP|WS_CHILD|WS_BORDER|WS_VISIBLE|LVS_AUTOARRANGE|LVS_REPORT |LVS_OWNERDATA ,
							 10, 114, 500, 300, hDlgs[3], 0, hInst, 0) ;
		SendMessage(hRepLV, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_GRIDLINES | LVS_EX_ONECLICKACTIVATE  | LVS_EX_FULLROWSELECT    ,
					LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_ONECLICKACTIVATE  ) ;
		SendMessage(hVDBLV, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_GRIDLINES | LVS_EX_ONECLICKACTIVATE  | LVS_EX_FULLROWSELECT    ,
					LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_ONECLICKACTIVATE  ) ;
		LVCOLUMN lvc ;
		//-------- add items to rep lv
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; 
		lvc.fmt = LVCFMT_LEFT ;
		lvc.cx = 205 ;
		lvc.pszText = "File path" ;
		lvc.iSubItem = 0;
		ListView_InsertColumn(hRepLV, 0, &lvc) ;
		lvc.pszText = "Result" ;
		lvc.iSubItem = 1;
		ListView_InsertColumn(hRepLV, 1, &lvc) ;
		lvc.cx = 80 ;
		lvc.pszText = "Actions" ;
		lvc.iSubItem = 2;
		ListView_InsertColumn(hRepLV, 2, &lvc) ;
		//-------- add items to vdb lv
		lvc.cx = 205 ;
		lvc.iSubItem = 0 ;
		lvc.pszText = "Virus name" ;
		ListView_InsertColumn(hVDBLV, 0, &lvc) ;
		lvc.cx = 50 ;
		lvc.iSubItem = 0 ;
		lvc.pszText = "Type" ;
		ListView_InsertColumn(hVDBLV, 1, &lvc) ;
		lvc.cx = 50 ;
		lvc.iSubItem = 2 ;
		lvc.pszText = "Sig size" ;
		ListView_InsertColumn(hVDBLV, 2, &lvc) ;
		lvc.cx = 205 ;
		lvc.iSubItem = 3 ;
		lvc.pszText = "Signature" ;
		ListView_InsertColumn(hVDBLV, 3, &lvc) ;
		return 0 ;
		
//##################### WM_PAINT
	case WM_PAINT :
		//-------- show left logo
		PAINTSTRUCT ps ;
		HDC hDC, hCDC ;
		hDC = BeginPaint(hWnd, &ps) ;
		hCDC = CreateCompatibleDC(hDC) ;
		SelectObject(hCDC, hBitmap) ;
        StretchBlt(hDC, 1, 0, 40, 500, hCDC, 0, 0, 40, 500, SRCCOPY) ;
		DeleteDC(hCDC) ;
		EndPaint(hWnd, &ps) ;
		return 0 ;
//##################### WM_SIZE
	case WM_SIZE :
		GetWindowRect(hWnd, &rect) ;
		MoveWindow(hTabControl, 50, 0, rect.right-rect.left, rect.bottom - rect.top, 1) ;
		return 0 ;
//##################### WM_NOTIFY
	case WM_NOTIFY :
		if(IsScaning)
				return 0 ;
		lpNMHDR = (LPNMHDR)lParam ;
		if( lpNMHDR->code != TCN_SELCHANGE )
			return 0 ;
		//====== show neded dlg
		switch( TabCtrl_GetCurSel((HWND)lpNMHDR->hwndFrom) )
		{
		//------ scan dlg need
		case 0 :
			ShowWindow(hDlgs[0], SW_SHOWDEFAULT) ;
			ShowWindow(hDlgs[1], SW_HIDE) ;
			ShowWindow(hDlgs[2], SW_HIDE) ;
			ShowWindow(hDlgs[3], SW_HIDE) ;
			ShowWindow(hDlgs[4], SW_HIDE) ;
			break ;
		//------ rep dlg need
		case 1 :
			ShowWindow(hDlgs[0], SW_HIDE) ;
			ShowWindow(hDlgs[1], SW_SHOWDEFAULT) ;
			ShowWindow(hDlgs[2], SW_HIDE) ;
			ShowWindow(hDlgs[3], SW_HIDE) ;
			ShowWindow(hDlgs[4], SW_HIDE) ;
			break ;
		//------- set dlg need
		case 2 :
			ShowWindow(hDlgs[0], SW_HIDE) ;
			ShowWindow(hDlgs[1], SW_HIDE) ;
			ShowWindow(hDlgs[3], SW_HIDE) ;
			ShowWindow(hDlgs[4], SW_HIDE) ;
			LoadSettings(hDlgs[2]) ;
			ShowWindow(hDlgs[2], SW_SHOWDEFAULT) ;
			break ;
		//-------- vdb edt dlg need
		case 3 :
			ShowWindow(hDlgs[0], SW_HIDE) ;
			ShowWindow(hDlgs[1], SW_HIDE) ;
			ShowWindow(hDlgs[2], SW_HIDE) ;
			ShowWindow(hDlgs[3], SW_SHOWDEFAULT) ;
			ShowWindow(hDlgs[4], SW_HIDE) ;
			break ;
		//-------- about dlg need
		case 4 :
			ShowWindow(hDlgs[0], SW_HIDE) ;
			ShowWindow(hDlgs[1], SW_HIDE) ;
			ShowWindow(hDlgs[2], SW_HIDE) ;
			ShowWindow(hDlgs[3], SW_HIDE) ;
			ShowWindow(hDlgs[4], SW_SHOWDEFAULT) ;
			break ;
		}
		return 0 ;

//##################### WM_CLOSE
	case WM_CLOSE :
		PostQuitMessage(0) ;
		return 0 ;
	}
	return DefWindowProc(hWnd, uMsg, wParam, lParam) ;
}
//################################ SCANDLGPROC ################################//
BOOL CALLBACK ScanDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	BROWSEINFO	bi ;
	
	switch(uMsg)
	{
//############### WM_INITDIALOG
	case WM_INITDIALOG :
		return 1 ;
//############### WM_CONTROL
	case WM_COMMAND :
		switch( LOWORD(wParam) )
		{
		//######### IDC_ADD_FILE_BTN
		case IDC_SCANDLG_ADDFILEBTN :
			ZeroMemory(&buff, sizeof(buff) ) ;
			ZeroMemory(&ofn, sizeof(ofn) ) ;
			ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST ;
			ofn.hInstance = hInst ;
			ofn.hwndOwner = hWnd ;
			ofn.lpstrFile = buff ;
			
			ofn.lpstrTitle = "Selecel object to scan : " ;
			ofn.lStructSize = sizeof(ofn) ;
			ofn.nMaxFile = sizeof(buff) ;
			GetCurrentDirectory(256, helpbuff) ;
			if( GetOpenFileName(&ofn) )
			{
			SetCurrentDirectory(helpbuff) ;
add_if_not_exist_in_list :
				hTargList = GetDlgItem(hDlg, IDC_SCANDLG_TARGLIST) ;
				//====== are there this file in the list ?
				
				for(int x=0; x < SendMessage( hTargList, LB_GETCOUNT, 0, 0 ) ; x++)
				{
					SendMessage( hTargList, LB_GETTEXT,x, (LPARAM)&tbuff) ;
					if( !lstrcmp( (LPCSTR)&(buff[0]), (LPCSTR)&(tbuff[0]) ) )
					{
						MessageBoxA(0,"Already in list", (LPCSTR)&(cWndName[0]), MB_ICONWARNING) ;
						return 1; 
					}
				}
				//====== no. add it.
				SendMessage( hTargList, LB_ADDSTRING, 0, LPARAM(& (buff[0]) ) ) ;
				
			}
			return 1;
	//######### IDC_ADDDIR_BTN
		case IDC_SCANDLG_ADDDIRBTN :
			ZeroMemory(&tbuff, sizeof(tbuff) ) ;
			ZeroMemory(&bi, sizeof(bi) ) ;
			bi.hwndOwner = hWnd ;
			bi.pszDisplayName = (LPSTR)&(buff[0]) ;
			bi.lpszTitle = "Select directory or drive to scan : " ;
			bi.ulFlags = BIF_SHAREABLE ;
			LPITEMIDLIST rez ;
			rez = SHBrowseForFolder( (LPBROWSEINFOA) &bi) ;
			if( rez )
			{
				//======== do normal path from fucked pid
				SHGetPathFromIDList(rez, (LPSTR)&buff) ;
				if(buff[lstrlen(buff)-1]!='\\')
					lstrcat( (LPTSTR)&buff, "\\") ;
				goto add_if_not_exist_in_list ;
			}
			return 1 ;
	//######### IDC_DEL_BTN
		case IDC_SCANDLG_DELBTN :
			int nCurSel ;
			nCurSel = (int)SendDlgItemMessage(hDlgs[0], IDC_SCANDLG_TARGLIST, LB_GETCURSEL, 0, 0) ;
			if( nCurSel==LB_ERR )
			{
				MessageBoxA(0, "You must select something before pushing DEL", (LPSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			SendDlgItemMessage(hDlgs[0], IDC_SCANDLG_TARGLIST, LB_DELETESTRING, \
							nCurSel , 0) ;
			return 1 ;

	//######### IDC_SCAN_BTN
		case IDC_SCANDLG_SCANBTN :
			if(!IsScaning)
			{
				DWORD dwID ;		// for win 9x support
				//--------- create suspenede wait thread
				hWaitTrd = CreateThread(0, 1000, (LPTHREAD_START_ROUTINE)WaitTrd, 0, CREATE_SUSPENDED, &dwID) ;
				//--------- launch scan thread
				hScanTrd = CreateThread(0, 1000, (LPTHREAD_START_ROUTINE)ScanTrd, 0, 0, &dwID ) ;
				if(!hScanTrd)
				{
					MessageBoxA(0, "Can't launch scan thread.", (LPCSTR)&cWndName, MB_ICONWARNING) ;
					TerminateThread(hWaitTrd, 0) ;
					IsScaning = 0 ;
					return 1 ;
				}
			}
			else
			{
				TerminateThread(phEmulTrd, 0) ;
				TerminateThread(hScanTrd, 0) ;
				return 1 ;
			}
			return 1 ;
	//########## IDC_PAUSE_BTN
		case IDC_SCANDLG_PAUSEBTN :
			if(IsPaused)
			{
				SetDlgItemText(hDlg, IDC_SCANDLG_PAUSEBTN, "Pause" ) ;
				SetDlgItemText(hDlg, IDC_SCANDLG_CURSCANEDT, (LPCTSTR)&statestr) ;
				ResumeThread(hScanTrd) ;
				IsPaused = 0 ;
				return 1 ;
			}
			else
			{
				IsPaused = 1 ;
				SetDlgItemText(hDlg, IDC_SCANDLG_PAUSEBTN, "Continue" ) ;
				GetDlgItemText(hDlg, IDC_SCANDLG_CURSCANEDT, (LPSTR)&statestr, sizeof(statestr) ) ;
				SetDlgItemText(hDlg, IDC_SCANDLG_CURSCANEDT, "Scan paused") ;
				SuspendThread(hScanTrd) ;
				return 1 ;
			}

		} //switch( LOWORD(wParam) )
		return 1 ;


	} //switch( uMsg )
	return 0 ;
}
//################################ REPORTDLGPROC################################//
BOOL CALLBACK ReportDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG :
		return 1 ;
	case WM_NOTIFY :
		LPNMHDR  lpnmh;
		lpnmh = (LPNMHDR) lParam;
		LV_DISPINFO *lpdi;
		lpdi = (LV_DISPINFO *)lParam;
		if( ((LPNMHDR)lParam)->code==LVN_GETDISPINFO)
		{
			switch (lpdi->item.iSubItem)
			{
				case 0:
					lpdi->item.pszText = pRepData[lpdi->item.iItem].path ;
					break;
		  
				case 1:
					lpdi->item.pszText = pRepData[lpdi->item.iItem].result ;
					break;

				case 2:
					switch( pRepData[lpdi->item.iItem].action )
					{
					case 0 : case -1 :
						lpdi->item.pszText = "no" ;
						break ;
					case 1 :
						lpdi->item.pszText = "Deleted" ;
						break ;
					case 2 :
						lpdi->item.pszText = "Cured" ;
						break ;
					case 3 :
						lpdi->item.pszText = "Moved to Q" ;
						break ;

					}
					break;

				default:
					break;
			}
		
		}
		return 1 ;	
	//########## wm_COMMAND
	case WM_COMMAND :
		switch( LOWORD(wParam) ) 
		{
		//######## DELTEET ACTION
		case IDC_REPORTDLG_DELETEACTIONBTN :
			nSel = SendMessage(hRepLV, LVM_GETSELECTIONMARK, 0, 0) ;
			if(nSel==-1)
			{
				MessageBox(0, "You must select something before pushing this button.", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			if( (pRepData[nSel].action == 1) || (pRepData[nSel].action == 3) )
			{
				MessageBox(0, "File already deleted or moved", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			if(!DeleteFile(pRepData[nSel].path))
			{
				MessageBox(0, "Can't delete specifed file" ,(LPCTSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			else
			{
				MessageBox(0, "File was successfuly deleted", (LPCTSTR)&cWndName, 0) ;
				pRepData[nSel].action=(BYTE)1 ;
			}
			ListView_Update( hRepLV, nSel ) ;
			return 1 ;
		//############ CURE ACTION
		case IDC_REPORTDLG_CUREACTIONBTN :
			nSel = SendMessage(hRepLV, LVM_GETSELECTIONMARK, 0, 0) ;
			if(nSel==-1)
			{
				MessageBox(0, "You must select something before pushing this button.", (LPCTSTR)&cWndName, 0) ;
				return 1 ;
			}
			if( pRepData[nSel].action != 0 )
			{
				MessageBox(0, "Can't cure file becouse file was changed by other action", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
				FreeLibrary(hScanLib) ;
				return 1 ;
			}
			HMODULE hHelLib ;
			HealProc pHP ;
			hHelLib = LoadLibrary("Cure.dll") ;
			if(!hHelLib)
			{
				MessageBox(0, "Can't load library \"Cure.dll\" ", (LPTSTR)&cWndName, 0) ;
				return 1 ;
			}
			pHP = (HealProc)GetProcAddress( hHelLib, pRepData[nSel].result ) ;
			if(!pHP)
				goto cant_cure_lb221 ;
			if( !pHP((BYTE *) &(pRepData[nSel].path ) ) )
			{
			cant_cure_lb221 :
				MessageBox(0, "Can't cure specifed file" ,(LPCTSTR)&cWndName, MB_ICONWARNING) ;
				FreeLibrary(hHelLib) ;
				return 1 ;
			}
			else
			{
				MessageBox(0, "File was successfuly cured", (LPCTSTR)&cWndName, 0) ;
				pRepData[nSel].action=(BYTE)2 ;
			}
			FreeLibrary(hHelLib) ;
			ListView_Update( hRepLV, nSel ) ;
			return 1 ;
		//############ MOVE TO Q BUTTON
		case IDC_REPORTDLG_MOVETOQACTIONBTN :
			ActionProc =(ActProc) GetProcAddress(hScanLib, "MoveToQAction") ;
			if(!ActionProc)
			{
				MessageBox(0, "Can't get proc address. \"kernel.dll\"Dll is probably damaged", (LPCTSTR)&cWndName, 0) ;
				return 1 ;
			}

			nSel = SendMessage(hRepLV, LVM_GETSELECTIONMARK, 0, 0) ;
			if(nSel==-1)
			{
				MessageBox(0, "You must select something before pushing this button.", (LPCTSTR)&cWndName, 0) ;
				return 1 ;
			}
			nSel*=256+256+1 ;
			if( (pRepData[nSel].action != 0) | (pRepData[nSel].action !=2) )
			{
				MessageBox(0, "Can't move to quarantine file becouse file was changed by other action", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			if( ActionProc((BYTE *)&pRepData[nSel].path,  (BYTE *)&pRepData[nSel].result) )
			{
				MessageBox(0, "Can't move to quarantine specifed file" ,(LPCTSTR)&cWndName, 0) ;
				return 1 ;
			}
			else
			{
				MessageBox(0, "File was successfuly moved", (LPCTSTR)&cWndName, 0) ;
				pRepData[nSel].action=(BYTE)3 ;
			}
			ListView_Update( hRepLV, nSel ) ;
			return 1 ;
		//################ SAVE REP
		case IDC_REPORTDLG_SAVEREPBTN :
			//------------- get file name
			HANDLE hSaveFile ;
			ZeroMemory(&buff, sizeof(buff) ) ;
			ZeroMemory(&ofn, sizeof(ofn) ) ;
			ofn.Flags = OFN_EXPLORER ;
			ofn.hInstance = hInst ;
			ofn.hwndOwner = hWnd ;
			ofn.lpstrFile = buff ;
			ofn.lpstrTitle = "Select file name : " ;
			ofn.lStructSize = sizeof(ofn) ;
			ofn.nMaxFile = sizeof(buff) ;
			GetCurrentDirectory(256, (LPSTR)&helpbuff) ;
			if( !GetSaveFileName(&ofn) )
			{
				SetCurrentDirectory((LPSTR)&helpbuff) ;
				return 1 ;
			}
			SetCurrentDirectory((LPSTR)&helpbuff) ;
			//-------------- open file
			hSaveFile = CreateFile((LPSTR)&buff, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,\
						FILE_ATTRIBUTE_NORMAL, 0) ;
			if(hSaveFile == INVALID_HANDLE_VALUE)
			{
				MessageBox(0, "Can't create file(Probably another application use this file). Try to chose other file.",\
							(LPCSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			DWORD nCounter, i;
			char Spliter[] = "   --   " ;
			nCounter = SendMessage(hRepLV, LVM_GETITEMCOUNT, 0, 0) ;
			for(i = 0 ; i < nCounter ; i++ )
			{
				WriteFile(hSaveFile, &(pRepData[i].path), lstrlen((LPCSTR)&(pRepData[i].path)), &rw, 0) ;
				WriteFile(hSaveFile, &Spliter, 8, &rw, 0) ;
				WriteFile(hSaveFile, &(pRepData[i].result), lstrlen((LPCSTR)&(pRepData[i].result)), &rw, 0) ;
				WriteFile(hSaveFile, &Spliter, 8, &rw, 0) ;
				switch(pRepData[i].action)
				{
				case 0x0 :
					lstrcpy( (LPSTR)&buff, "no action\r\n" ) ;
					break ;
				case 0x1 :
					lstrcpy( (LPSTR)&buff, "Deleted\r\n" ) ;
					break ;
				case 0x2 :
					lstrcpy( (LPSTR)&buff, "Cured\r\n" ) ;
					break ;
				case 0x3 :
					lstrcpy( (LPSTR)&buff, "Moved\r\n" ) ;
					break ;
				} // switch
				WriteFile(hSaveFile, &buff, lstrlen((LPSTR)&buff), &rw, 0) ;
			}// for
			//------ end of writing
			CloseHandle(hSaveFile) ;
			return 1 ;
		} // switch( LOWORD(wParam) ) 
		return 1 ;
	//############# DEFAULT
	}		// switch(uMsg)
	return 0 ;
}
//################################ SETTINGDLGPROC ################################//
BOOL CALLBACK SettingsDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
	//############ WM_COMMAND
	case WM_COMMAND :
		switch( LOWORD(wParam) )
		{
		//################### SAVE SETTINGS
		case IDC_SETTINGSDLG_SAVESETTINGSBTN :
			//----------------- save extensions
			DWORD x, Counter ;
			HANDLE hSetFile ; 
			hSetFile = CreateFile(sstruct.EPath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0) ;
			if(hSetFile == INVALID_HANDLE_VALUE)
			{
				MessageBox(0, "Can't open extensions file for write there new extensions", (LPCTSTR)&cWndName, 0) ;
				goto ext_write_failure ;
			}
			Counter = SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_GETCOUNT, 0, 0) ;
			buff[30] = 0 ;
			for(x=0; x < Counter ; x++)
			{
				SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_GETTEXT, x, (LPARAM)&buff) ;
				WriteFile(hSetFile, &buff, 30, &rw, 0) ;
			}
			CloseHandle(hSetFile) ;
			//----------------- save main settings
ext_write_failure :
			tsstruct = sstruct ;
			hSetFile = CreateFile("scanner.set", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, \
									FILE_ATTRIBUTE_NORMAL, 0) ;
			if(hSetFile == INVALID_HANDLE_VALUE)
			{
				MessageBox(0, "Can't open settings file", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			GetDlgItemText(hDlg, IDC_SETTINGSDLG_QUARANTINEEDT, sstruct.QPath, sizeof(sstruct.QPath) );
			GetDlgItemText(hDlg, IDC_SETTINGSDLG_EXTPATHEDT, sstruct.EPath, sizeof(sstruct.QPath) );
			sstruct.ScanMode = 0 ;
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_SIGSCANCB, BM_GETSTATE, 0, 0) == BST_CHECKED) 
				sstruct.ScanMode |= 0x1;
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_HERSCANCB, BM_GETSTATE, 0, 0) == BST_CHECKED) 
				sstruct.ScanMode |= 0x2;
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EMULCB, BM_GETSTATE, 0, 0) == BST_CHECKED) 
				sstruct.ScanMode |= 0x4;
			if( sstruct.ScanMode == 0 )
			{
				if(MessageBox(0, "Are you really wont to disable all modes of scan ?", \
					(LPCTSTR)&cWndName, MB_YESNO | MB_SYSTEMMODAL | MB_ICONWARNING ) != IDYES )
				{
					sstruct = tsstruct ;
					return 1 ;
				}
			}
			//------------ get action
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_AFARB, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.Action = 0x4 ;
				goto Action_got ;
			}
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_DELITRB, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.Action = 0x1 ;
				goto Action_got ;
			}
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_CURECB, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.Action = 0x2 ;
				goto Action_got ;
			}
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_MQUARANTINECB, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.Action = 0x3 ;
				goto Action_got ;
			}
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_NOACTIONCB, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.Action = 0x0 ;
				goto Action_got ;
			}
Action_got :
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_CQCB, BM_GETSTATE, 0, 0)==BST_CHECKED)
				sstruct.Action |= 0x80 ;
			//------------ get action
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_AFARB2, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.ccAction = 0x4 ;
				goto Action_got2 ;
			}
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_DELITRB2, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.ccAction = 0x1 ;
				goto Action_got2 ;
			}
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_MQUARANTINECB2, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.ccAction = 0x3 ;
				goto Action_got2 ;
			}
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_NOACTION2, BM_GETSTATE, 0, 0) == BST_CHECKED )
			{
				sstruct.ccAction = 0x0 ;
				goto Action_got2 ;
			}
Action_got2 :
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_CQCB2, BM_GETSTATE, 0, 0)==BST_CHECKED)
				sstruct.ccAction |= 0x80 ;
		//---------------- AOI
			if(SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_AOICB, BM_GETSTATE, 0, 0)==BST_CHECKED)
				sstruct.AOI = 1 ;
			else
				sstruct.AOI = 0 ;
		//----------------- emul sets
			sstruct.EmulTime =  GetDlgItemInt(hDlg, IDC_SETTINGSDLG_EMULTIMEEDT, 0, 0) ;
			sstruct.CheckStep =  GetDlgItemInt(hDlg, IDC_SETTINGSDLG_CHECKSTEPEDT, 0, 0) ;
		//---------------- write this shit to file
			if( !WriteFile(hSetFile, &sstruct, sizeof(sstruct), &rw, 0) )
				MessageBox(0, "Can't write settings to file", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
			CloseHandle(hSetFile) ;
			//--------refresh settings
			LoadExtensions(hDlg) ;
			return 1;
		//#################### LOAD DEF SETTINGS
		case IDC_SETTINGSDLG_SETTODEFBTN :
			hSetFile = CreateFile( "scanner.set", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, \
							FILE_ATTRIBUTE_NORMAL, 0) ;
			if( hSetFile == INVALID_HANDLE_VALUE )
			{
cant_create_settings_file :
				MessageBox(0, "Can't create settings file !", (LPSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			if(!WriteFile(hSetFile, &defset, sizeof(setstruct), &rw, 0) )
				goto cant_create_settings_file ;
			CloseHandle(hSetFile) ;
			LoadSettings(hDlg) ;
			return 1 ;

		//#################### ADD EXT
		case IDC_SETTINGSDLG_ADDEXTBTN :
			 DialogBox(hInst, MAKEINTRESOURCE(IDD_EXTADDDLG), hDlg, (DLGPROC)ExtAddDlgProc) ;
			 return 1;
		 //################## DEL EXT
		case IDC_SETTINGSDLG_DELEXTBTN :
			rw = (LRESULT) SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_GETCURSEL, 0, 0) ;
			if(rw==LB_ERR)
			{
				MessageBox(0, "You must select something before pushing this button", \
							  (LPCTSTR)&cWndName, 0) ;
				return 1;
			}
			SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_DELETESTRING, rw, 0) ;
			return 1;
		//################## CLR EXTS
		case IDC_SETTINGSDLG_CLREXTBTN :
			
			rw = SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_GETCOUNT, 0, 0) ;
			for(i ; i < rw ; i++)
				SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_DELETESTRING, 0, 0) ;
			return 1 ;
		//################# DEFAULT
		} //switch( LOWORD(wParam) )(WM_COMMAND)
		return 1;
	//############ WM_INITDIALOG
	case WM_INITDIALOG : 
		LoadSettings(hDlg) ;
		return 1 ;
	}
	return 0 ;
}
//###################################### VDBEditDlgProc ###############################//
BOOL CALLBACK VDBEditDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
	//######### WM_NOTIFY
	case WM_NOTIFY :
		LPNMHDR  lpnmh;
		lpnmh = (LPNMHDR) lParam;
		LV_DISPINFO *lpdi;
		lpdi = (LV_DISPINFO *)lParam;
		if( ((LPNMHDR)lParam)->code==LVN_GETDISPINFO)
		{
			switch (lpdi->item.iSubItem)
			{
				//--------- vir name
				case 0:
					lpdi->item.pszText = ppVDB[lpdi->item.iItem]->name ;
					break;
				//--------- tager type
				case 1:
					if((ppVDB[lpdi->item.iItem]->type)&1) 
						lpdi->item.pszText = "Any file" ;
					else
						lpdi->item.pszText = "PE file" ;
					break ;
				//--------- sig size
				case 2 :
					itoa( ppVDB[lpdi->item.iItem]->sig_size, &(buff[0]), 10 ) ;
					lpdi->item.pszText = &(buff[0]) ;
					break ;
				//--------- signature
				case 3 :
					BYTE b1 ;
					RtlZeroMemory( &(buff[0]), sizeof(buff) ) ;
					for(i = 0 ; i < ppVDB[lpdi->item.iItem]->sig_size ; i++ ) 
					{
						b1 = (BYTE)(*( (BYTE *)ppVDB[lpdi->item.iItem] + sizeof(sigstruct) + i) ) ;
						buff[i*3] = HexAlf[ (b1/16)%16 ] ;
						buff[i*3+1] = HexAlf[ b1%16 ] ;
						buff[i*3+2] = ' ' ;
					}
					lpdi->item.pszText = &(buff[0]) ;
					break ;
			}
		}
		return 1 ;

	//######### WM_COMMAND
	case WM_COMMAND :
		switch( LOWORD ( wParam ) )
		{
		//######### EDTSIG BTN
		case IDC_VDBEDTDLG_EDITSIGBTN :
			DialogBoxParam( hInst, MAKEINTRESOURCE( IDD_ADDSIGDLG ), hWnd, AddSigDlgProc, ListView_GetSelectionMark(hVDBLV) ) ;
			return 1 ;

		//######### ADDSIG BTN
		case IDC_VDBEDTDLG_ADDSIGBTN :
			if( DialogBoxParam( hInst, MAKEINTRESOURCE( IDD_ADDSIGDLG ), hWnd, AddSigDlgProc, VDBCounter ) == IDOK )
				VDBCounter ++ ;
			return 1 ;

		//######### DELSIG BTN
		case IDC_VDBEDTDLG_DELSIGBTN :
			rw = SendMessage( hVDBLV, LVM_GETSELECTIONMARK, 0, 0 ) ;
			if( rw == -1 )
			{
				MessageBox(0, "You must select something before pushing this button", (LPCTSTR)&cWndName, 0) ;
				return 1 ;
			}
			VDBCounter -- ;
			HeapFree( hAdditionalHeap, 0, ppVDB[rw] ) ;
			ListView_DeleteItem( hVDBLV, rw ) ;
			//VirtualFree(ppVDB[rw], ppVDB[rw]->sig_size + sizeof(sigstruct), MEM_RELEASE | MEM_DECOMMIT ) ;
			for( i = rw ; i < VDBCounter ; i ++)
				ppVDB[i] = ppVDB[i+1] ;
			//--- ret
			return 1 ;

		//######### UNLOAD VDBBTN
		case IDC_VDBEDTDLG_UNLOADVDBBTN :
			//-------- clear lv
			SendMessage( hVDBLV, LVM_DELETEALLITEMS, 0, 0) ;
			//-------- clear edits
			SetDlgItemText( hDlg, IDC_VDBEDTDLG_FILENAMEEDT, " " ) ;
			SetDlgItemText( hDlg, IDC_VDBEDTDLG_TOTALSIGEDT, " " ) ;
			SetDlgItemText( hDlg, IDC_VDBEDTDLG_VDBFILESIZEEDT, " " ) ;
			SetDlgItemText( hDlg, IDC_VDBEDTDLG_LASTUPDATEEDT, " " ) ;
			//-------- free mem and clear lv
			HeapDestroy(hAdditionalHeap) ;
			//-------- enable buttons
			hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_ADDSIGBTN ) ;
			EnableWindow( (HWND)hVDBFile, 0 ) ;
			hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_DELSIGBTN ) ;
			EnableWindow( (HWND)hVDBFile, 0 ) ;
			hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_EDITSIGBTN ) ;
			EnableWindow( (HWND)hVDBFile, 0 ) ;
			hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_SAVEVDBBTN ) ;
			EnableWindow( (HWND)hVDBFile, 0 ) ;
			hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_LOADVDBBTN ) ;
			EnableWindow( (HWND)hVDBFile, 1 ) ;
			hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_UNLOADVDBBTN ) ;
			EnableWindow( (HWND)hVDBFile, 0 ) ;
			//-------- ret
			return 1 ;
		//######### LOAD VDBBTN
		case IDC_VDBEDTDLG_LOADVDBBTN :
			//--------- open file
			ZeroMemory(&buff, sizeof(helpbuff) ) ;
			ZeroMemory(&ofn, sizeof(ofn) ) ;
			ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST ;
			ofn.hInstance = hInst ;
			ofn.hwndOwner = hWnd ;
			ofn.lpstrFile = helpbuff ;
			ofn.lpstrTitle = "Selecel database to load : " ;
			ofn.lStructSize = sizeof(ofn) ;
			ofn.nMaxFile = sizeof(helpbuff) ;
			GetCurrentDirectory(256, buff) ;
			if( GetOpenFileName(&ofn) )
			{
				SetCurrentDirectory(buff) ;
				//-------- show dialog
				SendMessage( hVDBLV, LVM_DELETEALLITEMS, 0, 0) ;
				//------ try to open file
				hVDBFile = CreateFile( (LPCTSTR)&helpbuff, GENERIC_READ, FILE_SHARE_READ, 0, \
													OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) ;
				if(hVDBFile == INVALID_HANDLE_VALUE )
				{
					MessageBox(0, "Can't open file", (LPCTSTR) &cWndName, MB_ICONWARNING) ;
					return 1 ;
				}
				//-------------- create heap
				hAdditionalHeap = HeapCreate(0, 7340032, 31457280) ;
				if( !hAdditionalHeap )
				{
					MessageBox(0, "Can't create additional heap", (LPTSTR)&cWndName, 0 );
					SendMessage( hVDBLV, LVM_DELETEALLITEMS, 0, 0) ;
					CloseHandle(hVDBFile) ;
					return 1 ; 
				}
				//-------------- load vdb
				ppVDB = (sigstruct **)HeapAlloc(hAdditionalHeap,HEAP_ZERO_MEMORY,  65536*4 ) ;
				if(!ppVDB)
				{
					MessageBox(0, "Can't alloc mem for pointers !", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
					CloseHandle( hVDBFile) ;
					SendMessage( hVDBLV, LVM_DELETEALLITEMS, 0, 0) ;
					return 1 ;
				}
				VDBSize = GetFileSize(hVDBFile, 0) ;
				if(VDBSize < 65536*8+4) 
				{
				vdbedt_invalid_file_format_lb :
					MessageBox(0, "Invalid file format", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
					CloseHandle( hVDBFile) ;
					SendMessage( hVDBLV, LVM_DELETEALLITEMS, 0, 0) ;
					return 1 ;
				}
				if( !ReadFile( hVDBFile, &VDBCounter, 4, &rw, 0) )
				{
				vdbedt_cant_read_file_lb :
					MessageBox(0, "Can't read file", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
					SendMessage( hVDBLV, LVM_DELETEALLITEMS, 0, 0) ;
					CloseHandle( hVDBFile) ;
					return 1 ;
				}
				SetFilePointer(hVDBFile, 524288+4, 0, FILE_BEGIN) ;
				if( VDBSize < VDBCounter * sizeof(sigstruct) )
					goto vdbedt_invalid_file_format_lb ;
				SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_HIGHEST ) ;
				for(i = 0 ; i < VDBCounter ; i++)
				{
					if( !ReadFile( hVDBFile, &t_sig_struct, sizeof(t_sig_struct), &rw, 0)  || rw != sizeof(t_sig_struct) )
					{
						SendMessage( hVDBLV, LVM_DELETEALLITEMS, 0, 0) ;
						goto vdbedt_cant_read_file_lb ;
					}
					ppVDB[i] = (sigstruct *)HeapAlloc(hAdditionalHeap, HEAP_ZERO_MEMORY,t_sig_struct.sig_size+sizeof(sigstruct) ) ;
					//------ if can't alloc mem for structure
					if( !ppVDB[i] )
					{
					vdbedt_cant_alloc_mem :
						SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_NORMAL ) ;
						SendMessage( hVDBLV, LVM_DELETEALLITEMS, 0, 0) ;
						MessageBox(0, "Can't alloc mem", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
						CloseHandle( hVDBFile) ;
						return 1 ;
					}
					//------ if mem allocated and all ok [yet]
					*ppVDB[i] = t_sig_struct ;
					//------- read sig to mem
					if( ( !ReadFile( hVDBFile, (BYTE *)ppVDB[i]+sizeof(sigstruct), t_sig_struct.sig_size, &rw, 0) ) || \
						( rw != t_sig_struct.sig_size ) ) 
					{
						SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_NORMAL ) ;
						MessageBox(0, "Can't read sig from file. Probably sig size is invalid", (LPTSTR)&cWndName, MB_ICONWARNING) ;
						CloseHandle(hVDBFile) ;
						return 1 ;
					}
					//------- add to lv
					lvi.mask = LVIF_TEXT |  LVIF_PARAM | LVIF_STATE; 
					lvi.state = 0; 
					lvi.stateMask = 0; 
					lvi.iItem = i;
					lvi.iSubItem = 0;
					lvi.lParam = (LPARAM) (ppVDB[i]);
						lvi.pszText = LPSTR_TEXTCALLBACK ;
						ListView_InsertItem(hVDBLV, &lvi) ;
					}
				SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_NORMAL ) ;
				SendMessage(hVDBLV, LVM_REDRAWITEMS, 0, VDBCounter) ;
				//------ fill file info group
				SetDlgItemText( hDlg, IDC_VDBEDTDLG_FILENAMEEDT, &(helpbuff[0]) ) ;
				SetDlgItemInt( hDlg, IDC_VDBEDTDLG_TOTALSIGEDT, VDBCounter, 0 ) ;
				SetDlgItemInt( hDlg, IDC_VDBEDTDLG_VDBFILESIZEEDT, VDBSize, 0 ) ;
				FILETIME VDBft ;
				SYSTEMTIME VDBst ;
				GetFileTime( hVDBFile, 0, 0, &VDBft) ;
				FileTimeToSystemTime( &VDBft, &VDBst) ;
				wsprintf( pcLastVdbUpdate, "%d.%d.%d", VDBst.wDay, VDBst.wMonth, VDBst.wYear ) ;
				SetDlgItemText( hDlg, IDC_VDBEDTDLG_LASTUPDATEEDT, pcLastVdbUpdate) ;
				CloseHandle(hVDBFile) ;
				//-------------- enable buttons
				hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_ADDSIGBTN ) ;
				EnableWindow( (HWND)hVDBFile, 1 ) ;
				hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_DELSIGBTN ) ;
				EnableWindow( (HWND)hVDBFile, 1 ) ;
				hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_EDITSIGBTN ) ;
				EnableWindow( (HWND)hVDBFile, 1 ) ;
				hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_SAVEVDBBTN ) ;
				EnableWindow( (HWND)hVDBFile, 1 ) ;
				hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_LOADVDBBTN ) ;
				EnableWindow( (HWND)hVDBFile, 0 ) ;
				hVDBFile = GetDlgItem( hDlg, IDC_VDBEDTDLG_UNLOADVDBBTN ) ;
				EnableWindow( (HWND)hVDBFile, 1 ) ;
				//--------------- ret
				SetCurrentDirectory((LPSTR)&buff) ;
				return 1 ;
			}
			return 1 ;
		//############ VDB SAVE BTN
		case IDC_VDBEDTDLG_SAVEVDBBTN :
			//------- get save file name
			ZeroMemory(&buff, sizeof(buff) ) ;
			ZeroMemory(&ofn, sizeof(ofn) ) ;
			ofn.Flags = OFN_EXPLORER ;
			ofn.hInstance = hInst ;
			ofn.hwndOwner = hWnd ;
			ofn.lpstrFile = buff ;
			ofn.lpstrTitle = "Select file name : " ;
			ofn.lStructSize = sizeof(ofn) ;
			ofn.nMaxFile = sizeof(buff) ;
			GetCurrentDirectory(256, (LPSTR)&helpbuff) ;
			if( !GetSaveFileName(&ofn) )
			{
				SetCurrentDirectory((LPSTR)&helpbuff) ;
				return 1 ;
			}
			SetCurrentDirectory((LPSTR)&helpbuff) ;
			//-------- create file
			hVDBFile = CreateFile( &buff[0], GENERIC_WRITE, 0, 0, CREATE_ALWAYS, \
									FILE_ATTRIBUTE_NORMAL, 0) ;
			if( hVDBFile == INVALID_HANDLE_VALUE )
			{
				MessageBox(0, "Can't create file.", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
				return 1 ;
			}
			//---------- write to file
			if( !WriteFile( hVDBFile, &VDBCounter, 4, &rw, 0) || ( rw != 4 ) )
				goto vdbsave_cant_write_to_file ;
			SetFilePointer( hVDBFile, 524288+4, 0, FILE_BEGIN) ;
			DWORD *search_table ;
			search_table = (DWORD *)VirtualAlloc(0, 65536*8, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ) ;
			if( !search_table )
			{
				MessageBox(0, "Can't alloc mem for search_table", (LPTSTR)&cWndName, 0 ) ;
				CloseHandle(hVDBFile) ;
				DeleteFile( (LPTSTR)&buff[0] ) ;
				return 1 ;
			}
			RtlZeroMemory( search_table, 65536*8 ) ;
			DWORD dwtCounter ;
			DWORD j ;
			SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_HIGHEST ) ;
			for( j = 0x0000, dwtCounter = 0 ; j < 0x10000 ; j++, dwtCounter =  0 )
			{
					for(i = 0 ; i < VDBCounter ; i ++)
					{
						if( *((WORD *)( (BYTE *)ppVDB[i] + sizeof(sigstruct) )) == j)
						{
							if( !dwtCounter )
								*(search_table+j+1) = SetFilePointer(hVDBFile, 0, 0, FILE_CURRENT) ;	
							dwtCounter++;
							if( !WriteFile(hVDBFile, ppVDB[i], ppVDB[i]->sig_size + sizeof(sigstruct), \
											&rw, 0) || ( rw != (ppVDB[i]->sig_size + sizeof(sigstruct) ) ) )
							{
							vdbsave_cant_write_to_file :
								SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_NORMAL ) ;
								VirtualFree( search_table, 65536*8, MEM_DECOMMIT | MEM_RELEASE ) ;
								MessageBox(0, "Can't write to file !", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
								CloseHandle(hVDBFile) ;
								DeleteFile(&buff[0]) ;
								return 1 ;
							}
						}
					}
					*(search_table+j)= dwtCounter ;
			}
				SetFilePointer(hVDBFile, 4, 0, FILE_BEGIN) ;
				if( !WriteFile(hVDBFile, search_table, sizeof(search_table), &rw, 0) )
					goto vdbsave_cant_write_to_file ;
			//------- clear and ret
			SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_NORMAL ) ;
			CloseHandle( hVDBFile) ;
			return 1 ;
		} // SWITCH ( LOWORD ( wParam ) )
		
	} // switch(uMsg)*/
	return 0 ;
}
//###################################### AboutDlgProc ###############################//
BOOL CALLBACK AboutDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG :
		SetDlgItemText( hDlg , IDC_ABOUTDLG_DESCREDT, description_text ) ;
		return 1 ;
	}
	return 0 ;
	
	
		
}
//###################################### Scan thread ###############################//
void	ScanTrd(DWORD p1)
{
	RtlZeroMemory(&statestr, sizeof(statestr) ) ;
	if(pRepFile)
	{
		nRepICounter = ListView_GetItemCount( hRepLV ) ;
		//-------- del all items
		for(i=0; i < nRepICounter; i++)
			ListView_DeleteItem(hRepLV, 0) ;
		//-------- unmap file
		UnmapViewOfFile(pRepData );
		CloseHandle(hMapFile) ;
		CloseHandle(hRepFile) ;
		pRepFile = 0 ;
	}
	int nCount ;
	nCount = (int)SendMessage(hTargList, LB_GETCOUNT, 0, 0) ;
	if(!nCount)
	{
		MessageBox(0, "You must add something to scan before pushing this button.", (LPSTR)&cWndName, 0) ;
		TerminateThread(hWaitTrd, 0) ;
		IsScaning = 0 ;
		ExitThread(0) ;
	}
	hScanLib = LoadLibrary("kernel.dll") ;
			if(!hScanLib)
			{
				MessageBoxA(0, "Error load library! Can't scan ! Try to restart program!", (LPSTR)&cWndName, MB_ICONWARNING) ;
				TerminateThread(hWaitTrd, 0) ;
				IsScaning = 0 ;
				IsPaused = 0 ;
				ExitThread(0) ;
			}
			SCANPROC proc ;
			proc = (SCANPROC)GetProcAddress( hScanLib, "Scan" ) ;
			if(!proc)
			{
				MessageBoxA(0, "kernel.dll probably damaged. Try to reinstall application or repair it", (LPSTR)&cWndName, MB_ICONWARNING) ;
				TerminateThread(hWaitTrd, 0) ;
				IsScaning = 0 ;
				IsPaused = 0 ;
				ExitThread(0) ;
			}
			pEdt =( HANDLE * ) GetProcAddress(hScanLib, "hCurScanEdt") ;
			pMpb =( HANDLE * ) GetProcAddress(hScanLib, "hMPB") ;
			pRepFile = ( HANDLE * ) GetProcAddress(hScanLib, "hRepFile") ;
			phEmulTrd = ( HANDLE * ) GetProcAddress(hScanLib, "hEmulTrd") ;
			setstruct **pSet ;
			pSet = (setstruct **)GetProcAddress( hScanLib, "pSet" ) ;
			if( (!pEdt) || (!pMpb) || (!pRepFile) || (!pSet) || (!phEmulTrd) )
			{
				MessageBox(0, "Dll is probably damaged. Try to reinstall app", (LPCSTR)&cWndName, 0 ) ;
				IsScaning = 0 ;
				IsPaused = 0 ;
				TerminateThread(hWaitTrd, 0) ;
				ExitThread(0) ;
				return ;
			}
			*pSet = &sstruct ;
			*pEdt = GetDlgItem(hDlgs[0], IDC_SCANDLG_CURSCANEDT) ;
			*pMpb = GetDlgItem(hDlgs[0], IDC_SCANDLG_SCANPB) ;
		
			BYTE *pBuff ;
			pBuff =(BYTE *) VirtualAlloc(0, nCount*257, MEM_COMMIT, PAGE_READWRITE) ;
			if(!pBuff)
			{
				MessageBoxA(0, "Can't alloc buffer. No enought memory. Try to close some programs", (LPCSTR)&cWndName, MB_ICONWARNING) ;
cant_scan_lb :
				TerminateThread(hWaitTrd, 0) ;
				IsScaning = 0 ;
				IsPaused = 0 ;
				ExitThread(0) ;
			}
			ResumeThread(hWaitTrd) ;
			for(i = 0 ; i < nCount; i ++) 
			{
				SendMessage( hTargList, LB_GETTEXT,i, (LPARAM)&tbuff) ;
				lstrcpy( (LPSTR)(pBuff+i*257), (LPCSTR)&tbuff ) ;
			}
			HANDLE hExtFile ;
			hExtFile = CreateFile(sstruct.EPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) ;
			if(hExtFile==INVALID_HANDLE_VALUE)
			{
				MessageBox(0, "Can't open extensions file", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
				goto cant_scan_lb ;
			}
			nECounter = GetFileSize(hExtFile, 0) ;
			
			pexts = 0 ;
			if(nECounter)
			{
				if(nECounter%30)
				{
					MessageBox(0, "Invalid file of extensions", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
					goto cant_scan_lb ;
				}
				pexts = (BYTE *) VirtualAlloc(0, nECounter, MEM_COMMIT, PAGE_READWRITE ) ;
				if(!pexts)
				{
					MessageBox(0, "Can't alloc mem for exts", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
					goto cant_scan_lb ;
				}
				ReadFile(hExtFile, pexts, nECounter, &rw, 0) ;
			}// if
			CloseHandle(hExtFile) ;
			if( proc(pBuff, nCount, pexts, nECounter/30) )
			{
				MessageBox(0, "Scan failure", (LPTSTR)&cWndName, 0) ;
			}
			ExitThread(0) ;
}

//######################################### WAIT thread ################################################3//
void WaitTrd(DWORD p1)
{
//-------- init some varz
	IsScaning = 1 ;
	IsPaused =  0 ;
//-------- disable some buttons and set some text
	SendDlgItemMessage(hDlgs[0], IDC_SCANDLG_PAUSEBTN, WM_SETTEXT, 0, (LPARAM)"Pause") ;
	SendDlgItemMessage(hDlgs[0], IDC_SCANDLG_SCANBTN, WM_SETTEXT, 0, (LPARAM)"Stop") ;
	EnableWindow( GetDlgItem(hDlgs[0], IDC_SCANDLG_ADDFILEBTN), 0 );
	EnableWindow( GetDlgItem(hDlgs[0], IDC_SCANDLG_ADDDIRBTN), 0 );
	EnableWindow( GetDlgItem(hDlgs[0], IDC_SCANDLG_DELBTN), 0 );
	EnableWindow( GetDlgItem(hDlgs[0], IDC_SCANDLG_PAUSEBTN), 1 );
	
//--------- wait for scan
	WaitForSingleObject(hScanTrd, INFINITE) ;	
//--------- scan finished
	MessageBox(0, "Scan finished", (LPCSTR)&cWndName, 0) ;
//--------- enable buttons
	SendDlgItemMessage(hDlgs[0], IDC_SCANDLG_SCANBTN, WM_SETTEXT, 0, (LPARAM)"Scan") ;
	SendDlgItemMessage(hDlgs[0], IDC_SCANDLG_PAUSEBTN, WM_SETTEXT, 0, (LPARAM)"Pause") ;
	EnableWindow( GetDlgItem(hDlgs[0], IDC_SCANDLG_ADDFILEBTN), 1 );
	EnableWindow( GetDlgItem(hDlgs[0], IDC_SCANDLG_ADDDIRBTN), 1 );
	EnableWindow( GetDlgItem(hDlgs[0], IDC_SCANDLG_DELBTN), 1 );
	EnableWindow( GetDlgItem(hDlgs[0], IDC_SCANDLG_PAUSEBTN), 0 );
	SendDlgItemMessage( hDlgs[0], IDC_SCANDLG_SCANPB, PBM_SETPOS, 0, 0) ;//SendMessage((HWND) *pMpb, PBM_SETPOS, 0, 0) ;
//---------- free some mem
	VirtualFree(pexts, nECounter, MEM_DECOMMIT) ;
//---------- free liv
	hRepFile = *pRepFile ;
	FreeLibrary( hScanLib ) ;
//---------- set some varz
	IsScaning = 0 ;
	IsPaused =  0 ;
//---------- form report 
	SetDlgItemText(hDlgs[0], IDC_SCANDLG_CURSCANEDT, "Forming report...") ;
	if( FormReport(hRepFile) )
	{
		MessageBox(0, "Can't form report. Maybe can't alloc mem or open file \"last.rep\"", (LPCTSTR)&cWndName, MB_ICONWARNING) ;	
		SetDlgItemText(hDlgs[0], IDC_SCANDLG_CURSCANEDT, "Waiting for command.") ;
		ExitThread(0) ;
	}
	SetDlgItemText(hDlgs[0], IDC_SCANDLG_CURSCANEDT, "Waiting for command.") ;
//---------- show report dlg
	TabCtrl_SetCurSel(hTabControl, 1) ;
	ShowWindow(hDlgs[0], SW_HIDE) ;
	ShowWindow(hDlgs[1], SW_SHOWDEFAULT) ;
	ShowWindow(hDlgs[2], SW_HIDE) ;		
//--------- ret
	ExitThread(0) ;
}


//########################################## FORM REPORT ########################################//
inline BYTE FormReport(HANDLE hFile) // ret 0 if succ and 1 if fuck
{
	DWORD fsize = GetFileSize(hFile, 0) ;
	DWORD nCounter = fsize / (256+256+1) ;
	if(!nCounter) // if nothing found
		return 0 ;
	hMapFile = CreateFileMapping(hFile, 0, PAGE_READWRITE, 0, fsize, 0 );
	if(!hMapFile)
		return 1 ;
	pRepData = (istruct *)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0) ;
	if(!pRepData)
		return 1 ;
	DWORD x ;
	//--- del all items
	for(x=0; x < nRepICounter; x++)
		ListView_DeleteItem(hRepLV, 0) ;
	//--- add new items
	for(x=0; x < nCounter; x++)
	{
		lvi.mask = LVIF_TEXT |  LVIF_PARAM | LVIF_STATE; 
		lvi.state = 0; 
		lvi.stateMask = 0; 
		lvi.iItem = x;
		lvi.iSubItem = 0;
		lvi.lParam = (LPARAM) &(pRepData[x]);
		lvi.pszText = LPSTR_TEXTCALLBACK ;
		ListView_InsertItem(hRepLV, &lvi) ;
	}
	nRepICounter = nCounter ;
	return 0 ;
}
//##################################### EXT ADD DLG PROC ##############################//
BOOL CALLBACK ExtAddDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
	//########## WM_COMMAND
	case WM_COMMAND :
		switch( LOWORD(wParam) )
		{
		case IDOK :
			GetDlgItemText(hDlg, IDC_ADDEXTDLG_EXTEDT, (LPTSTR)&buff, sizeof(buff) ) ;
			SendDlgItemMessage(hDlgs[2], IDC_SETTINGSDLG_EXTLISTLB, LB_ADDSTRING, 0, (LPARAM)&buff) ;
		case IDCANCEL :
			EndDialog(hDlg, 0) ;
			return 1; 
		}
		return 1 ;
	}
	return 0 ;
}
//##################################### SIGEDTPROC ####################################//
LRESULT SigEdtProc( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	if( uMsg == WM_CHAR )
	{
		BYTE chr ;
		chr = (BYTE) wParam ;
		if( (chr >= 'a') & (chr <= 'f') )
		{
			wParam-= 0x20 ;
			chr = wParam ;
		}
		
		if( (chr >= '0') & (chr <= '9') || (chr >= 'A') & (chr <= 'F') || (chr==' ')  || (chr==VK_RETURN) || (chr == VK_DELETE)\
			|| (chr==VK_LEFT) || (chr==VK_RIGHT) || (chr==VK_DOWN) || (chr==VK_UP) || (chr==VK_BACK))
			return CallWindowProc( OriginSigEdtProc, hWnd, uMsg, wParam, lParam ); 
		else	
			return 0 ;
	}
	return CallWindowProc( OriginSigEdtProc, hWnd, uMsg, wParam, lParam ); 
}
//##################################### SIG ADD DLG PROC ##############################//
BOOL CALLBACK AddSigDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) // ERROR
{
	switch(uMsg)
	{
	//######## WM_INITDIALOG
	case WM_INITDIALOG :
		//----------- superclass sig edt
		OriginSigEdtProc = (WNDPROC) SetWindowLong( GetDlgItem(hDlg, IDC_ADDSIGDLG_SIGEDT), GWL_WNDPROC, (LONG)SigEdtProc ) ;
		//----------- do some init
		SendDlgItemMessage( hDlg, IDC_ADDSIGDLG_VIRTYPECB, CB_ADDSTRING, 0, (LPARAM)"PE file") ;
		SendDlgItemMessage( hDlg, IDC_ADDSIGDLG_VIRTYPECB, CB_ADDSTRING, 0, (LPARAM)"Any file") ;
		SendDlgItemMessage( hDlg, IDC_ADDSIGDLG_VIRTYPECB, CB_SETCURSEL, 0, 0) ;
		SendDlgItemMessage( hDlg, IDC_ADDSIGDLG_VIRNAMEEDT, EM_SETLIMITTEXT, 30, 0) ;
		dwCur = lParam ;
		if(lParam < VDBCounter )
		{
			//------------ save old data
			CopyMemory( &VDBOldItem, ppVDB[dwCur], sizeof(sigstruct) + ppVDB[dwCur]->sig_size ) ;
			//------------ do init
			SetDlgItemText( hDlg, IDC_ADDSIGDLG_VIRNAMEEDT, (LPCTSTR)ppVDB[dwCur] ) ;
			SendDlgItemMessage( hDlg, IDC_ADDSIGDLG_VIRTYPECB, CB_SETCURSEL, ppVDB[dwCur]->type, 0) ;
			SetDlgItemInt( hDlg, IDC_ADDSIGDLG_SIGSIZEEDT, ppVDB[dwCur]->sig_size, 0 ) ;
			BYTE b1 ;
			RtlZeroMemory( &(buff[0]), sizeof(buff) ) ;
			for(i = 0 ; i < ppVDB[dwCur]->sig_size ; i++ ) 
			{
				b1 = (BYTE)(*( (BYTE *)ppVDB[dwCur] + sizeof(sigstruct) + i) ) ;
				buff[i*3] = HexAlf[ (b1/16)%16 ] ;
				buff[i*3+1] = HexAlf[ b1%16 ] ;
				if( i != ppVDB[dwCur]->sig_size-1 )
					buff[i*3+2] = ' ' ;
			}
			SetDlgItemText(hDlg, IDC_ADDSIGDLG_SIGEDT, (LPCTSTR)(&buff[0])) ;
		}
		return 1 ;
	//######## WM_COMMAND
	case WM_COMMAND :
		switch( LOWORD( wParam ) )
		{
		//########### calc sig size
		case IDC_ADDSIGDLG_CALCSIGSIZEBTN :
			dwBuffSize = GetDlgItemText(hDlg, IDC_ADDSIGDLG_SIGEDT, &buff[0], sizeof(buff) ) ;
			DWORD x ;
			
			
			for( i = 0, dwSigSize = 0, x = 1  ; i < dwBuffSize ; i ++, x++ )
			{
				if( buff[i] == 0x0D )
				{
					x-=3 ;
					i++; 
					dwSigSize ++ ;
					continue ;
				}
				if( (buff[i] == ' ') && (x%3) )
					goto bad_sig_foramt_calc ;
				if( ( (buff[i] == ' ')  &&  !( x % 3)  ) || (i == dwBuffSize) )
					dwSigSize ++ ;
			}
			dwSigSize++;
			SetDlgItemInt(hDlg, IDC_ADDSIGDLG_SIGSIZEEDT, dwSigSize, 0) ;
			return 1 ;
			bad_sig_foramt_calc :
				MessageBox(0, "Invalid signature format. Read readme.htm for more info", (LPTSTR)&cWndName, 0) ;
				return 1 ;
		//########### OK BTN
		case IDOK :
			dwSigSize = GetDlgItemInt(hDlg, IDC_ADDSIGDLG_SIGSIZEEDT, 0, 0) ;
			if( dwSigSize > 255 )
			{
				MessageBox(0, "Max signature size = 255 !", (LPCTSTR)&cWndName, MB_ICONWARNING ) ;
				return 1 ;
			}
			if( dwCur < VDBCounter )
				HeapFree(hAdditionalHeap, 0, ppVDB[dwCur] ) ;
			ppVDB[dwCur] = (sigstruct *)HeapAlloc( hAdditionalHeap, 0, sizeof(sigstruct) + dwSigSize ) ;
			if( !ppVDB[dwCur] )
			{
				MessageBox(0, "Can't alloc mem", (LPTSTR)&cWndName, 0) ;
			}
			GetDlgItemText( hDlg, IDC_ADDSIGDLG_VIRNAMEEDT, &buff[0], 30 ) ;
			lstrcpy( (LPSTR)&(t_sig_struct.name), &(buff[0]) ) ;
			t_sig_struct.sig_size = dwSigSize ; 
			t_sig_struct.type = SendDlgItemMessage( hDlg, IDC_ADDSIGDLG_VIRTYPECB, CB_GETCURSEL, 0, 0) ;
			*ppVDB[dwCur] = t_sig_struct ;
			//---------- recode sig
			dwBuffSize = GetDlgItemText(hDlg, IDC_ADDSIGDLG_SIGEDT, (LPSTR)&(buff[0]), sizeof(buff) ) ;
			if( dwBuffSize  < (dwSigSize*3-1) )
			{
				bad_sig_format :
				if( dwCur < VDBCounter )
				{
					HeapFree( hAdditionalHeap, 0, ppVDB[dwCur]) ;
					if( !(ppVDB[dwCur] = (sigstruct *)HeapAlloc( hAdditionalHeap, 0, sizeof(sigstruct) + VDBOldItem.sig_size ) ) )
					{
						MessageBox(0, "Can't alloc mem", (LPTSTR)&(cWndName[0]), 0) ;
						ListView_DeleteItem(hVDBLV, dwCur) ;
						for(i = dwCur ; i < VDBCounter-1 ; i++)
							ppVDB[i] = ppVDB[i+1] ;
						return 1 ;
					}
					CopyMemory( ppVDB[dwCur], &VDBOldItem, sizeof(sigstruct) + VDBOldItem.sig_size ) ; 
				}
				MessageBox(0, "Invalid signature format ! Reenter data", (LPTSTR)&cWndName, MB_ICONWARNING ) ;
				return 1 ;
			}
			BYTE bC, bM ;
			for(x = 1 , i = 0, bC = 0 ; i < dwBuffSize ; i++, x++ )
			{
				if( buff[i] == 0x0D )
				{
					x = 0;
					i++ ;
					x-=3 ;
					bC++; 
					continue ;
				}
				if( (buff[i]==' ') && (x%3) )
					goto bad_sig_format ;
				if( (buff[i] == ' ' ) && !(x%3) )
				{
					x = 0 ;
					bC++ ;
					continue ;
				}
				
				if( buff[i] >= 'A' )
					*( (BYTE *)ppVDB[dwCur] + sizeof(sigstruct) + bC ) += ( buff[i] - 'A' + 10 ) * ( (x%2) ? 16 : 1 ) ;
				else
					*( (BYTE *)ppVDB[dwCur] + sizeof(sigstruct) + bC ) += ( buff[i] - '0' ) * ( (x%2) ? 16 : 1 ) ;
			}
			
			if( dwCur < VDBCounter )
				goto update_vdb_lv ;
			//---------- add to lv
			lvi.mask = LVIF_TEXT |  LVIF_PARAM | LVIF_STATE; 
			lvi.state = 0; 
			lvi.stateMask = 0; 
			lvi.iItem = i;
			lvi.iSubItem = 0;
			lvi.lParam = (LPARAM) (ppVDB[i]);
			lvi.pszText = LPSTR_TEXTCALLBACK ;
			ListView_InsertItem(hVDBLV, &lvi)  ;
		update_vdb_lv :
			SendMessage( hVDBLV, LVM_REDRAWITEMS, 0, VDBCounter) ;
			//---------- exit dialog
		//######### CANCLE BTN
		case IDCANCEL :
			EndDialog( hDlg, LOWORD(wParam) ) ;
			return 1 ;
		} // switch(loword(wparam) ) // wm_command
	return 1 ;
	} // switch(uMsg)
	return 0 ;
}
//###################################### LOAD SETTINGS ###############################//
inline int LoadSettings(HWND hDlg)
{
//---------- load settings
	//--------- open fucked file, if it can't be opened then fuck with user
	hSetFile = CreateFile( "scanner.set", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, \
							FILE_ATTRIBUTE_NORMAL, 0) ;
	if(hSetFile==INVALID_HANDLE_VALUE)
	{
		if( MessageBox(0, "Can't open \"scanner.set\" file.\nThis file contain settings for scanner.\nAre you gonna to \
create new file with default settings ?", (LPTSTR)&cWndName, MB_YESNO | MB_ICONWARNING) == IDYES)
		{
			hSetFile = CreateFile( "scanner.set", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, 0, CREATE_ALWAYS, \
							FILE_ATTRIBUTE_NORMAL, 0) ;
			if(hSetFile == INVALID_HANDLE_VALUE)
			{
				MessageBox(0, "Can't create file ! Shit! Shit! Shit! What did you do with you computer last night ?", \
					(LPTSTR)&cWndName, MB_ICONWARNING );
				return 1 ;
			}
			if( !WriteFile(hSetFile, &defset, sizeof(setstruct), &rw, 0 ) )
			{
				MessageBoxA(0, "Can't write def settings to file! Shit !", (LPTSTR)&cWndName, MB_ICONWARNING) ;
				CloseHandle( hSetFile ) ;
				return 1 ;
			}
			goto process_options ;
		}
		ExitProcess(0) ;
	}
	//------------- set all 
process_options :
	SetFilePointer(hSetFile, 0, 0, FILE_BEGIN)  ;
	ReadFile(hSetFile, &(sstruct), sizeof(setstruct), &rw, 0) ;
	CloseHandle(hSetFile ) ;
	SetDlgItemText(hDlg, IDC_SETTINGSDLG_QUARANTINEEDT, sstruct.QPath) ;
	SetDlgItemText(hDlg, IDC_SETTINGSDLG_EXTPATHEDT, sstruct.EPath) ;
	//---------- when found virus what to do ?
	switch(sstruct.Action)
	{
	case 0x4 : default :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_AFARB, BM_CLICK, 0, 0) ;
		break ;
	case 0x3 :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_MQUARANTINECB, BM_CLICK, 0, 0) ;
		break ;
	case 0x2 :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_CURECB, BM_CLICK, 0, 0) ;
		break ;
	case 0x1 :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_DELITRB, BM_CLICK, 0, 0) ;
		break ;
	case 0x0 :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_NOACTIONCB, BM_CLICK, 0, 0) ;
		break ;
	}
	switch(sstruct.ccAction)
	{
	case 0x4 : default :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_AFARB2, BM_CLICK, 0, 0) ;
		break ;
	case 0x3 :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_MQUARANTINECB2, BM_CLICK, 0, 0) ;
		break ;
	case 0x1 :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_DELITRB2, BM_CLICK, 0, 0) ;
		break ;
	case 0x0 :
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_NOACTION2, BM_CLICK, 0, 0) ;
		break ;
	}
	if(sstruct.Action & 0x80 )
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_CQCB, BM_SETCHECK, BST_CHECKED, 0) ;
	if(sstruct.ccAction & 0x80 )
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_CQCB2, BM_SETCHECK, BST_CHECKED, 0) ;
	//-------scan mode
	if(sstruct.ScanMode & 0x01)
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_SIGSCANCB, BM_SETCHECK, BST_CHECKED, 0) ;
	else
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_SIGSCANCB, BM_SETCHECK, BST_UNCHECKED, 0) ;
	if(sstruct.ScanMode & 0x02)
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_HERSCANCB, BM_SETCHECK, BST_CHECKED, 0) ;
	else
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_HERSCANCB, BM_SETCHECK, BST_UNCHECKED, 0) ;
	if(sstruct.ScanMode & 0x4 )
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EMULCB, BM_SETCHECK, BST_CHECKED, 0) ;
	else
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EMULCB, BM_SETCHECK, BST_UNCHECKED, 0) ;
	//-------report settings
	if(sstruct.AOI)
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_AOICB, BM_SETCHECK, BST_CHECKED, 0) ;
	else
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_AOICB, BM_SETCHECK, BST_UNCHECKED, 0) ;
	//------- emul settings
	SetDlgItemInt(hDlg, IDC_SETTINGSDLG_EMULTIMEEDT, sstruct.EmulTime, 0) ;
	SetDlgItemInt(hDlg, IDC_SETTINGSDLG_CHECKSTEPEDT, sstruct.CheckStep, 0) ;
	//------- extensions
	LoadExtensions(hDlg) ;
	return 1; 
}

//########################### LOAD EXTENSIONS #############################//
inline int LoadExtensions(HWND hDlg)
{
	HANDLE hSetFile ;
hSetFile = CreateFile(  sstruct.EPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0,\
							OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) ; 
	if(!hSetFile)
	{
		MessageBox(0, "Can't open extensions file", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
		return 1 ;
	}
	DWORD nECounter, x ;
	nECounter = SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_GETCOUNT, 0, 0 ) ;
	for(x = 0 ; x < nECounter ; x++)
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_DELETESTRING, 0, 0) ;
	nECounter = GetFileSize(hSetFile, 0) ;
	if(nECounter%30)
	{
		MessageBox(0, "Invalid extensions file!", (LPCTSTR)&cWndName, MB_ICONWARNING) ;
		CloseHandle(hSetFile) ;
		return 1 ;
	}
	nECounter /= 30 ;
	SetFilePointer(hSetFile, 0, 0, FILE_BEGIN) ;
	buff[30] = 0 ;
	for (x = 0 ; x < nECounter ; x++)
	{
		ReadFile(hSetFile, &buff, 30, &rw, 0) ;
		SendDlgItemMessage(hDlg, IDC_SETTINGSDLG_EXTLISTLB, LB_ADDSTRING, 0, (LPARAM)&buff) ;
	}
	CloseHandle(hSetFile) ;
	return 0 ;
}


//################################### WAIT DLG PROC #########################################//
BOOL CALLBACK WaitDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch( uMsg )
	{
	//############### WM_INITDIALOG 
	case WM_INITDIALOG :
		hWaitDlg = hDlg ;
		SetWindowText( hDlg, ((WAITDLGPARAM_T *)(lParam))->add_buff) ;
		ResumeThread(((WAITDLGPARAM_T *)(lParam))->hThread) ;
		return 1 ;
	//################# WM_COMMAND
	case WM_COMMAND :
		switch( LOWORD( wParam ) )
		{
		//########## CANCEL
		case IDCANCEL :
			TerminateThread(hLoadVdbTrd, 1) ;
			return 1 ;
		}
		return 1;
	}
	return 0 ;
}