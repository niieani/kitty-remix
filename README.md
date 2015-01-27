How to compile KiTTY under MingW
================================
[See this guide](https://nesity.improwizuj.pl/2013/09/17/how-to-compile-putty-or-kitty-under-mingw/)

How to compile KiTTY under Visual Studio 2013
=============================================

1. Install [VS 2013](http://download.microsoft.com/download/7/1/B/71BA74D8-B9A0-4E6C-9159-A8335D54437E/vs_community.exe)
2. ```git clone --recursive <kitty-remix>```
3. In VS, open solution ```kitty-remix/putty/windows/VS2013/putty.sln```
4. BUILD / Configuration Manager / Active solution configuration: set to *Release*
5. Build (F7)
6. If everything went right, files can be found in ```kitty-remix/putty/windows/VS2013/<tool>/Release/<tool.exe>```