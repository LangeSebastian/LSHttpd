QT += core network
QT -= gui

CONFIG += c++11

TARGET = LSHttpdTest
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

CONFIG(debug, debug|release){
    macx {
        DESTDIR = $$OUT_PWD
        LIBS += -L$$OUT_PWD/..
    } else {
        DESTDIR = $$OUT_PWD/../debug
    }
    LIBS += -L$$DESTDIR -llshttpdd
}

CONFIG(release, debug|release){
    macx {
        DESTDIR = $$OUT_PWD
        LIBS += -L$$OUT_PWD/..
    } else {
        DESTDIR = $$OUT_PWD/../release
    }
    LIBS += -L$$DESTDIR -llshttpd
}

INCLUDEPATH += $$_PRO_FILE_PWD_/..


SOURCES += main.cpp

ADDITIONAL_FILES += LSHttpd.crt \
                    LSHttpd.key \
                    index.html

OTHER_FILES += $$ADDITIONAL_FILES


