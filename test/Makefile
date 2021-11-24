#
# Makefile to compile COTP
#
.SUFFIXES: .o .cpp
.PHONY: all debug release clean

CC = g++

CCFLAGS = -finput-charset=utf-8 -fPIC

debug: CCFLAGS += -ggdb -Wall -Wno-deprecated-declarations -O0

release: CCFLAGS += -O2

# Special flags

INCPATH += -I. -I../src -I../deps/QR-Code-generator

# LIBRARY
LIBPATH += -L..

LIBS = -lcotp

# https://stackoverflow.com/questions/38254115/best-practice-for-c-program-with-plugins-in-linux
RPATH = -Wl,-rpath=..

# Linker
LDFLAGS = -rdynamic $(LIBPATH) $(LIBS) $(RPATH)

##############################################################################################################################

OUT = cotp_test

SRC = cotp_test.cpp

OBJ = ${SRC:.cpp=.o}

###############################################################################################################################

all debug release: $(OUT)

$(OUT): $(OBJ)
	$(CC) -o$@ $(OBJ) $(LDFLAGS)

clean:
	rm -f *~ $(OUT) $(OBJ) hotp.svg totp.svg totp_sha1.svg totp_sha256.svg totp_sha512.svg

%.o: %.cpp
	$(CC) $(CCFLAGS) $(INCPATH) -c $< -o $@
