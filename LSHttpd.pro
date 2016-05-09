#-------------------------------------------------
#
# Project created by QtCreator 2016-05-09T11:20:19
#
#-------------------------------------------------

QT       += network

QT       -= gui

TARGET = LSHttpd
TEMPLATE = lib

DEFINES += LSHTTPD_LIBRARY

SOURCES += lshttpd.cpp \
    lshttpdprivate.cpp

HEADERS += lshttpd.h\
        lshttpd_global.h \
    lshttpdprivate.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}

DISTFILES += \
    .gitignore
