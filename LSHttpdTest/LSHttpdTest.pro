QT += core network
QT -= gui

CONFIG += c++11

TARGET = LSHttpdTest
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

INCLUDEPATH += $$_PRO_FILE_PWD_/..
LIBS += -L$$_PRO_FILE_PWD_/libs -llshttpd

SOURCES += main.cpp


CONFIG(debug, debug|release){
    DESTDIR = ../debug
}

CONFIG(release, debug|release){
    DESTDIR = ../release
}
