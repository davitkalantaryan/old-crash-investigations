#
# File doocs_server_common.pri
# File created : 12 Feb 2017
# Created by : Davit Kalantaryan (davit.kalantaryan@desy.de)
# This file can be used to produce Makefile for daqadcreceiver application
# for PITZ
#

message("!!! doocs_server_common.pri:")

QT -= core
QT -= gui
LIBS += -lEqServer
include(../../common/common_qt/doocs_client_common.pri)

