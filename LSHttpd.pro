#-------------------------------------------------
#
# Project created by QtCreator 2016-05-09T11:20:19
#
#-------------------------------------------------

QT       += network core
QT       -= gui

CONFIG += c++11

lessThan(QT_MAJOR_VERSION, 5) {
    message(This library requires Qt version >= 5.3)
}

equals(QT_MAJOR_VERSION, 5) {
    lessThan(QT_MINOR_VERSION, 5) {
        lessThan(QT_MINOR_VERSION, 3) {
            message(This library requires Qt version >= 5.3)
        }
        else
        {
            message(Compatibility mode for Qt version < 5.5)
            DEFINES += LS_COMPATIBILITY_MODE_QT53
        }
    }
}

TARGET = LSHttpd
CONFIG(debug, debug|release) {
    TARGET = LSHttpdd
}

TEMPLATE = lib

DEFINES += LSHTTPD_LIBRARY

SOURCES += lshttpd.cpp \
    lshttpdprivate.cpp \
    http-parser/http_parser.c \
    lshttpdresource.cpp

HEADERS += lshttpd.h \
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
