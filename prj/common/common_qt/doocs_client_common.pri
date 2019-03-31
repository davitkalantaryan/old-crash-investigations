#
# File doocs_client_common.pri
# File created : 12 Feb 2017
# Created by : Davit Kalantaryan (davit.kalantaryan@desy.de)
# This file can be used to produce Makefile for daqadcreceiver application
# for PITZ
#

MYDOOCS = /afs/ifh.de/group/pitz/doocs

message("!!! doocs_client_common.pri:")

include(../../common/common_qt/sys_common.pri)
SYSTEM_LIB = $$MYDOOCS/system_arch/$$CODENAME/lib
message("!!! SYSTEM_LIB: $$SYSTEM_LIB")

DEFINES += LINUX

#LIBS += -L/doocs/lib
LIBS += -L$$SYSTEM_LIB
#LIBS += -L/doocs/develop/kalantar/programs/cpp/works/sys/$$CODENAME/lib
#LIBS += -L/doocs/develop/bagrat/doocs.git/amd64_rhel60/lib
LIBS += -lDOOCSapi
LIBS += -lldap
LIBS += -lrt

include(../../common/common_qt/sys_common.pri)

INCLUDEPATH += $$SYSTEM_LIB/include/doocs
#INCLUDEPATH += /doocs/develop/bagrat/doocs.git/include
