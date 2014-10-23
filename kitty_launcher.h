#ifndef KITTY_LAUNCHER_H
#define KITTY_LAUNCHER_H

#include <windows.h>

void GoNext( HWND hwnd ) ;
void GoPrevious( HWND hwnd ) ;
int WINAPI Launcher_WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmdline, int show) ;

#endif
