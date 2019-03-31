# File daqcollector_common.pri
# File created : 02 Feb 2017
# Created by : Davit Kalantaryan (davit.kalantaryan@desy.de)
# This file can be used to produce Makefile for daqadcreceiver application
# for PITZ
message("!!! daqcollector_common.pri:")
include(../../common/common_qt/root_no_gui_common.pri)
DEFINES += ROOT_APP

# call qmake CONFIG+=test
optionsTest = $$find(CONFIG, "1test")
count(optionsTest, 1):message("!!! test1 version") DEFINES += TEST_VERSION111
options = $$find(CONFIG, "2test")
count(options, 1):message("!!! test2 version") DEFINES += TEST_VERSION112
include(../../common/common_qt/doocs_server_common.pri)
equals(CODENAME,"Boron") { 
    message ("!!!!! No cpp 11 used")
    DEFINES += no_cpp11
}
else { 
    message ("!!!!! cpp 11 is used")
    QMAKE_CXXFLAGS += -std=c++0x
}
INCLUDEPATH += ../../../include
INCLUDEPATH += ../../../src/tools

# these two lines are just for inteligence
INCLUDEPATH += /afs/ifh.de/@sys/products/root64/5.20.00/include
INCLUDEPATH += /doocs/lib/include
SOURCES += ../../../src/server/pitz_daq_collectorproperties.cpp \
    ../../../src/tmp/mailsender.cpp \
    ../../../src/cpp11/thread_cpp11.cpp \
    ../../../src/utils/pitz_daq_memory.cpp \
    ../../../src/server/pitz_daq_singleentry.cpp \
    ../../../src/cpp11/mutex_cpp11.cpp \
    ../../../src/common/common_rwlock.cpp \
    ../../../src/server/pitz_daq_eqfctcollector.cpp \
    ../../../src/server/pitz_daq_collector_global.cpp
HEADERS += ../../../src/server/pitz_daq_collectorproperties.hpp \
    ../../../include/thread_cpp11.impl.hpp \
    ../../../include/thread_cpp11.hpp \
    ../../../include/common_defination.h \
    ../../../include/pitz_daq_memory.hpp \
    ../../../include/common_fifofast.impl.hpp \
    ../../../include/common_fifofast.hpp \
    ../../../src/server/pitz_daq_singleentry.hpp \
    ../../../include/mutex_cpp11.hpp \
    ../../../include/common_unnamedsemaphorelite.hpp \
    ../../../include/common/rwlock.hpp \
    ../../../src/server/pitz_daq_eqfctcollector.hpp
