
message ("investigator.pro") 

TEMPLATE = lib
include(../../common/common_qt/sys_common.pri)

INCLUDEPATH += $${PWD}/../../../include

LIBS += -ldl
LIBS += -lpthread
LIBS += -lc

SOURCES  += \
    $${PWD}/../../../src/investigator/crash_investigator_unix_gcc.cpp
	
HEADERS += \
    $${PWD}/../../../include/crash_investigator.h

OTHER_FILES += \
    $${PWD}/../../../src/investigator/crash_investigator.c \
    $${PWD}/../../../src/investigator/crash_investigator_microsoft.c \
    $${PWD}/../../../src/investigator/crash_investigator_unix.cpp \
    $${PWD}/../../../src/investigator/crash_investigator_windows.c \
    $${PWD}/../../../src/investigator/crash_investigator_gcc.cpp
