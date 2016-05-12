#include <QCoreApplication>

#include <QHostAddress>
#include <lshttpd.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    LSHttpd *h = new LSHttpd(QHostAddress::Any,8089,true);
    h->setCertificate("LSHttpd.crt");
    h->setPrivateKey("LSHttpd.key");
    return a.exec();
}
