QT += core network
QT -= gui

CONFIG += c++11

TARGET = LSHttpdTest
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

CONFIG(debug, debug|release){
    DESTDIR = ../debug
}

CONFIG(release, debug|release){
    DESTDIR = ../release
}

INCLUDEPATH += $$_PRO_FILE_PWD_/..
LIBS += -L$$DESTDIR -llshttpd

SOURCES += main.cpp


