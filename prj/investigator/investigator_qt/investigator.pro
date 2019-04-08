
message ("investigator.pro") 
include(../../common/common_qt/sys_common.pri)

#QMAKE_CFLAGS += -rdynamic
#QMAKE_CXXFLAGS += -rdynamic
#QMAKE_LFLAGS += -rdynamic
QMAKE_CXXFLAGS_WARN_ON += -Wimplicit-fallthrough=0

INCLUDEPATH += $${PWD}/../../../include

LIBS += -ldl

SOURCES  += \
    $${PWD}/../../../src/investigator/main_investigator.cpp \
    $${PWD}/../../../src/investigator/crash_investigator_unix_gcc.cpp
	
HEADERS += \
    $${PWD}/../../../include/crash_investigator.h

OTHER_FILES += \
    $${PWD}/../../../src/investigator/crash_investigator.c \
    $${PWD}/../../../src/investigator/crash_investigator_microsoft.c \
    $${PWD}/../../../src/investigator/crash_investigator_unix.cpp \
    $${PWD}/../../../src/investigator/crash_investigator_unix_02.cpp \
    $${PWD}/../../../src/investigator/crash_investigator_windows.c \
    $${PWD}/../../../src/investigator/crash_investigator_gcc.cpp \
    $${PWD}/../../../src/investigator/crash_investigator_unix_gcc.cpp
