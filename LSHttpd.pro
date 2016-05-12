#-------------------------------------------------
#
# Project created by QtCreator 2016-05-09T11:20:19
#
#-------------------------------------------------

QT       += network
QT       -= gui

CONFIG += c++11

TARGET = LSHttpd
TEMPLATE = lib

DEFINES += LSHTTPD_LIBRARY

SOURCES += lshttpd.cpp \
    lshttpdprivate.cpp \
    http-parser/http_parser.c \
    lshttpdresource.cpp

HEADERS += lshttpd.h\
        lshttpd_global.h \
        lshttpdprivate.h \
        http-parser/http_parser.h \
    lshttpdresource.h


unix {
    target.path = /usr/lib
    INSTALLS += target
}

DISTFILES += \
    .gitignore
