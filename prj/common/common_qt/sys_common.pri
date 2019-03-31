# File sys_common.pri
# File created : 12 Feb 2017
# Created by : Davit Kalantaryan (davit.kalantaryan@desy.de)
# This file can be used to produce Makefile for daqadcreceiver application
# for PITZ
#

#QMAKE_CXXFLAGS_WARN_ON += -Wno-unused-parameter
#QMAKE_CXXFLAGS_WARN_ON += -Wno-unused-variable
#QMAKE_CXXFLAGS_WARN_ON += -Wno-sign-compare
#QMAKE_CXXFLAGS_WARN_ON += -Wno-unused-function
#QMAKE_CXXFLAGS_WARN_ON -= -Wunused-function

DEEPNESS = ../../..

optionsLib = $$find(TEMPLATE, "lib")

count(optionsLib, 1){
equals(TARGET_EXT,"mex*"){
    TARGET_PATH=mbin
    message("Matlab mex file creation")
}else{
    TARGET_PATH=lib
    DEEPNESS = ../../../../
    message("Shared library creation")
}
}else{
    TARGET_PATH=bin
    DEEPNESS = ../../../../
    message("Binary file creation")
}


win32{
    CODENAME = win64
    SYSTEM_PATH = sys/win64
    }else {
        macx{
            CODENAME = mac
            SYSTEM_PATH = sys/mac
        }else {
            DEFINES += LINUX
            CODENAME = $$system(lsb_release -c | cut -f 2)
            SYSTEM_PATH = sys/$$CODENAME
        }
}

message("!!! sys_common.pri: SYSTEM_PATH=$$SYSTEM_PATH")

# Debug:DESTDIR = debug1
DESTDIR = $$DEEPNESS/$$SYSTEM_PATH/$$TARGET_PATH
OBJECTS_DIR = ../../../$$SYSTEM_PATH/.objects
CONFIG += debug

#CONFIG += c++11
#QMAKE_CXXFLAGS += -std=c++0x
# greaterThan(QT_MAJOR_VERSION, 4):QT += widgets
#QT -= core
#QT -= gui
