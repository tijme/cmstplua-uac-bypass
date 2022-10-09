BOFNAME := UACBypassCMSTPLUA
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all:
	$(CC_x64) -c ./$(BOFNAME).c -o ./$(BOFNAME).x64.o -masm=intel -DBOF 
	$(CC_x86) -c ./$(BOFNAME).c -o ./$(BOFNAME).x86.o -masm=intel -DBOF 
	$(CC_x64) ./$(BOFNAME).c -o ./$(BOFNAME).x64.exe -masm=intel -lole32 -loleaut32
	$(CC_x86) ./$(BOFNAME).c -o ./$(BOFNAME).x86.exe -masm=intel -lole32 -loleaut32
