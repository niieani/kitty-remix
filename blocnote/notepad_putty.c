#include <time.h>

HWND ParentWindow = NULL ;		// HWND de la fenêtre parente

char * get_param_str( char * str ) ;

void TestIfParentIsKiTTY( void ) {
	ParentWindow = GetForegroundWindow() ;
	char buffer[256] ;
	GetClassName( ParentWindow, buffer, 256 ) ;
	if( strcmp( buffer, "KiTTY" ) && strcmp( buffer, "PuTTY" ) ) ParentWindow = NULL ;
		//SendMessage(ParentWindow, WM_CHAR, buffer[i], 0) ; 
	}

void ActiveParent( void ) { if( IsIconic( ParentWindow ) ) ShowWindow(ParentWindow,SW_RESTORE) ; }
	
void SendStr2Window( HWND hwnd, char * buffer ) {
	int i ; 
	if( strlen( buffer) > 0 ) {
		for( i=0; i< strlen( buffer ) ; i++ ) 
			if( buffer[i] == '\n' ) { SendMessage( hwnd, WM_KEYDOWN, VK_RETURN, 0 ) ; }
			else if( buffer[i] == '\r' ) { }
			else SendMessage( hwnd, WM_CHAR, buffer[i], 0 ) ;
		}
	}

void Send2Parent( char * buffer ) {
	if( (ParentWindow != NULL) && (buffer!=NULL) ) {
		//ActiveParent() ;
		SendStr2Window( ParentWindow, buffer ) ;
		}
	}

void InitKiTTYNotepad( HWND hwnd ) {
	if( ParentWindow!=NULL ) {
		int pw=0, ph=0, px=0, py=0 ;
		RECT Rect ;
		GetWindowRect( ParentWindow, &Rect ) ;
		px=Rect.left+20 ; 
		py=Rect.top+20 ;
		pw=Rect.right-Rect.left+1 ;
		ph=Rect.bottom-Rect.top+1 ;
		SetWindowPos(hwnd, NULL, px, py, pw, ph, SWP_NOZORDER) ;
		}
	}

static int CRLF_flag = 1 ;
static int Semic_flag = 1 ;
static int Slash_flag = 0 ;
	
// Fonction pour envoyer une chaîne à la fenetre parente
void SendStrToParent( HWND hWndEdit ) {
	char buffer[32000] = "" ;
	int d,f,i;
	char CharLim = '\n' ;
	
	if( Semic_flag ) CharLim = ';' ;
	if( Slash_flag ) CharLim = '/' ;
	if( CRLF_flag ) CharLim = '\n' ;
	
	GetWindowText(hWndEdit,buffer,32000);
	SendMessage( hWndEdit, EM_GETSEL, (WPARAM)&d, (LPARAM)&f ) ;
	
	if( d==f ) {
		while( (d>0)&&(buffer[d-1]!=CharLim) ) d-- ;
		while( (buffer[f]!=CharLim)&&(buffer[f]!='\0') ) f++ ;
			
		if( buffer[f-1] != CharLim ) { buffer[f] = CharLim ; buffer[f+1] = '\0' ; f++ ; }
		else { buffer[f] = '\0' ; }
		
		SendMessage( hWndEdit, EM_SETSEL, (WPARAM)d, (LPARAM)f ) ;
		}
	else buffer[f] = '\0' ;

	if( Slash_flag ) if( buffer[f-1]=='/' ) {
		i = f-2 ;
		while( (i>0)&&( (buffer[i]==' ')||(buffer[i]=='	')||(buffer[i]=='\n')||(buffer[i]=='\r') ) ) i-- ;
		if( (i>0) && (buffer[i]==';') ) buffer[f-1]=' ' ;
		}

	if( CRLF_flag && (buffer[strlen(buffer)-1]!='\n') ) strcat( buffer, "\n" ) ;

//sprintf( buffer,"#%d -> %d#",d,f);MessageBox(hWndEdit, buffer,"Info",MB_OK);GetWindowText(hWndEdit,buffer,32000);
	if( strlen(buffer)>0 ) {
		if( IsIconic( ParentWindow ) ) { 
			ShowWindow(ParentWindow,SW_RESTORE) ;
			Send2Parent( buffer+d ) ;
			SetForegroundWindow( GetParent( hWndEdit ) ) ;
			}
		else {
			BringWindowToTop( ParentWindow ) ;
			Send2Parent( buffer+d ) ;
			BringWindowToTop( GetParent( hWndEdit ) ) ;
			}
		SetFocus( hWndEdit ) ;
		SendMessage( hWndEdit, EM_SETSEL, (WPARAM)d, (LPARAM)d ) ;
		}
	}

void SetWindowsSize( HWND hwnd ) {
	//int w=GetSystemMetrics(SM_CXSCREEN), h=GetSystemMetrics(SM_CYSCREEN) ;
	int w=GetSystemMetrics(SM_CXFULLSCREEN), h=GetSystemMetrics(SM_CYFULLSCREEN) ;

	//char buffer[256];
	//sprintf( buffer, "%d %d %d %d",w,h,GetSystemMetrics(SM_CXFULLSCREEN),GetSystemMetrics(SM_CYFULLSCREEN));
	//MessageBox(hwnd, buffer,"Info",MB_OK);
	
	//SetWindowPos(ParentWindow, NULL, 0, 0, w, (int)(h/2.), SWP_NOZORDER) ;
	//SetWindowPos(hwnd, NULL, 0, (int)(h/2.)+1, w, h, SWP_NOZORDER) ;
	
	MoveWindow( ParentWindow, 0, 0, w, (int)(h/2.), TRUE );
	MoveWindow( hwnd, 0, (int)(h/2.)+1, w, (int)(h/2.), TRUE );
	}
