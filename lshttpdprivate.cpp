#include "lshttpdprivate.h"

LSHttpdPrivate::LSHttpdPrivate(QHostAddress address, quint16 port, bool useSSL, LSHttpd *q) : QTcpServer(q), q_ptr(q)
{

}


void LSHttpdPrivate::incomingConnection(qintptr handle)
{
}
