#
# File root_no_gui_common.pri
# File created : 02 Feb 2017
# Created by : Davit Kalantaryan (davit.kalantaryan@desy.de)
# This file can be used to produce Makefile for daqadcreceiver application
# for PITZ
#


MYROOTSYS = /afs/ifh.de/@sys/products/root64/5.20.00
MYROOTCFLAGS = `$$MYROOTSYS/bin/root-config \
    --cflags`
QMAKE_CXXFLAGS += $$MYROOTCFLAGS
QMAKE_CFLAGS += $$MYROOTCFLAGS
optionsCpp11 = $$find(CONFIG, "cpp11")
count(optionsCpp11, 1):QMAKE_CXXFLAGS += -std=c++0x
message("!!! root_no_gui_common.pri: ROOT_FLAGS=$$MYROOTCFLAGS")

LIBS += -L/doocs/develop/kalantar/programs/cpp/works/pitz-daq/sys/$$CODENAME/lib
LIBS += $$system($$MYROOTSYS/bin/root-config --libs)
