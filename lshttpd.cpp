#include "lshttpd.h"
#include "lshttpdprivate.h"

LSHttpd::LSHttpd(QHostAddress address, quint16 port, bool useSSL) : d_ptr(new LSHttpdPrivate(address, port, useSSL, this))
{

}
