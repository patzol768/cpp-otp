#
# Makefile to compile COTP
#

# Compile options
SSL=true
QR=true

OUT = libcotp.so
TEST = test/cotp_test

##############################################################################################################################

.SUFFIXES: .o .cpp
.PHONY: all debug release clean

CC = g++

CCFLAGS = -finput-charset=utf-8 -fPIC

debug: CCFLAGS += -ggdb -Wall -Wno-deprecated-declarations -O0

release: CCFLAGS += -O2 -std=c++11

all: release

INCPATH += -I.

# Linker
#LDFLAGS = -shared -rdynamic -Wl,-init,init_lib
LDFLAGS = -shared -rdynamic

# OpenSSL

ifeq ($(SSL),true)
	LIBS += -lcrypto
else
	CCFLAGS += -DNO_OPENSSL
endif

ifeq ($(QR),true)
	QR_LIB_NAME = qrcodegencpp
	QR_LIB_DIR = deps/QR-Code-generator
	QR_LIB_FILE = $(QR_LIB_DIR)/lib$(QR_LIB_NAME).a
	INCPATH += -I$(QR_LIB_DIR)
	LIBS += -l$(QR_LIB_NAME)
	LDFLAGS += -L$(QR_LIB_DIR)
	SRC += src/qr_code.cpp
else
	CCFLAGS += -DNO_QR
	QR_LIB_FILE = .noqr
endif

##############################################################################################################################

SRC += src/cotp.cpp src/otp_uri.cpp src/otp_factory.cpp

OBJ = ${SRC:.cpp=.o}

###############################################################################################################################

all debug release: $(OUT) $(TEST)

$(OUT): $(OBJ) $(QR_LIB_FILE)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

$(QR_LIB_FILE):
ifeq ($(QR),true)
	make -C deps/QR-Code-generator $(@F)
else
	touch $@
endif

$(TEST):
	make -C test $(@F)

clean:
	rm -f *~ $(OUT) $(OBJ)
ifneq ($(QR),true)
	rm $(QR_LIB_FILE)
endif
	make -C deps/QR-Code-generator $@
	make -C test $@

%.o: %.cpp
	$(CC) $(CCFLAGS) $(INCPATH) -c $< -o $@

