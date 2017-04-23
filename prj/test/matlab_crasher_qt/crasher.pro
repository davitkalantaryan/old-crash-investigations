#
# File remote_call.pro
# File created : 19 Apr 2017
# Created by : Davit Kalantaryan (davit.kalantaryan@desy.de)
# This file can be used to produce Makefile for daqadcreceiver application
# for PITZ
#

include(../../common/common_qt/mex_common.pri)

#TARGET = remote_call
#CONFIG += c++11

INCLUDEPATH += ../../../include

SOURCES += \
    ../../../src/test/mex_crasher.cpp
