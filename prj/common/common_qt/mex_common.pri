#
# File mex_common.pri
# File created : 19 Apr 2017
# Created by : Davit Kalantaryan (davit.kalantaryan@desy.de)
# This file can be used to produce Makefile for daqadcreceiver application
# for PITZ
#


TARGET_EXT = mexa64
QMAKE_EXTENSION_SHLIB = mexa64

include(../../common/common_qt/sys_common.pri)

equals(CODENAME,"Santiago"){
    INCLUDEPATH += /products/matlab/R2010a/extern/include
}else{
    equals(CODENAME,"trusty"){
        INCLUDEPATH += /usr/local/MATLAB/R2016a/extern/include
}}

TEMPLATE = lib
QMAKE_EXTRA_TARGETS += copy_mex_file
#copy_mex_file.commands = "cp "
POST_TARGETDEPS += copy_mex_file

QT -= core
QT -= gui
