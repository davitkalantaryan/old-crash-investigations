
message ("investigator.pro") 
include(../../common/common_qt/sys_common.pri)

SOURCES  += \
	$${PWD}/../../../src/investigator/main_investigator.cpp \
	$${PWD}/../../../src/investigator/crash_investigator.c
	
HEADERS += \
	$${PWD}/../../../include/crash_investigator.h 
