#ifndef LSHTTPDPRIVATE_H
#define LSHTTPDPRIVATE_H

#include <QTcpServer>
#include <QObject>

class LSHttpdPrivate : public QTcpServer
{
public:
    LSHttpdPrivate(QHostAddress address, quint16 port, bool useSSL, LSHttpd *q);

    // QTcpServer interface
protected:
    LSHttpd *q_ptr;

    void incomingConnection(qintptr handle) Q_DECL_OVERRIDE;
};

#endif // LSHTTPDPRIVATE_H
