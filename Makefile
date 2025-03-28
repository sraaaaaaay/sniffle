# Sniffle makefile

CC = gcc
CFLAGS = -Wall -Wextra
NPCAP_SDK = C:/npcap-sdk
INCLUDES = -I"./include" -I"$(NPCAP_SDK)/Include"
LIBS = "C:/Windows/System32/wpcap.dll" "C:/Windows/System32/Packet.dll" -lws2_32
EXE = sniffle.exe

all: $(EXE)

$(EXE): src/main.c
	$(CC) $(CFLAGS) -I$(INCLUDES) -o $@ $< $(LIBS)

clean:
	del $(EXE)