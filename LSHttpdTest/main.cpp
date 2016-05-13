#include <QCoreApplication>

#include <QObject>
#include <QHostAddress>
#include <lshttpd.h>
#include <lshttpdresource.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    LSHttpd *h = new LSHttpd(QHostAddress::Any,8089,true);
    h->setCertificate("LSHttpd.crt");
    h->setPrivateKey("LSHttpd.key");

    auto res = h->registerFallback();
    QObject::connect(res.data(),&LSHttpdResource::pendingRequest,[=](LSHttpdRequest* request){
        request->response404();
    });
    return a.exec();
}
