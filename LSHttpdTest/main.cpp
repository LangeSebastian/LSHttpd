#include <QCoreApplication>

#include <QObject>
#include <QHostAddress>
#include <lshttpd.h>
#include <lshttpdresource.h>
#include <QFile>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    LSHttpd *h = new LSHttpd(QHostAddress::Any,8089,true);
    h->setCertificate("LSHttpd.crt");
    h->setPrivateKey("LSHttpd.key");

    auto res404fallback = h->registerFallback();
    QObject::connect(res404fallback.data(),&LSHttpdResource::pendingRequest,[=](LSHttpdRequest* request){
        request->response404();
    });
    auto res204 = h->registerResource(QRegularExpression("^/article$"));
    QObject::connect(res204.data(),&LSHttpdResource::pendingRequest,[=](LSHttpdRequest* request){
        request->response204();
    });
    auto resCustom = h->registerResource(QRegularExpression("^/index.html$"));
    QObject::connect(resCustom.data(),&LSHttpdResource::pendingRequest,[=](LSHttpdRequest* request){
        QFile file("index.html");
        if(file.exists())
        {
            if(file.open(QIODevice::ReadOnly))
            {
                QByteArray data = file.readAll();
                QList<LSHttpdHeaderPair> list;
                LSHttpdHeaderPair contentType;
                contentType.first = "Content-Type";
                contentType.second = "text/html; charset=UTF-8";
                list.append(contentType);
                request->createResponse(LSHttpdRequest::OK,list,data);
                request->sendResponse();
            }
        }
    });

    return a.exec();
}
