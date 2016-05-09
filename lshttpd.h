#ifndef LSHTTPD_H
#define LSHTTPD_H

#include "lshttpd_global.h"

#include <QObject>
#include <QTcpServer>
#include <QHostAddress>
#include <QTcpSocket>

class LSHttpdPrivate;

class LSHTTPDSHARED_EXPORT LSHttpd
{

public:
    LSHttpd(QHostAddress address=QHostAddress::Any, quint16 port, bool useSSL=false);

protected:
    LSHttpd(LSHttpdPrivate &d);
    LSHttpdPrivate *d_ptr;

};

#endif // LSHTTPD_H
