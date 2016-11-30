#include <QCoreApplication>

#include <QObject>
#include <QHostAddress>
#include <lshttpd.h>
#include <lshttpdresource.h>
#include <QFile>
#include <QUuid>
#include <QCryptographicHash>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    LSHttpd *h = new LSHttpd(QHostAddress::Any,8089,false);
    h->setCertificate("LSHttpd.crt");
    h->setPrivateKey("LSHttpd.key");

    auto res404fallback = h->registerFallback();
    QObject::connect(res404fallback.data(),&LSHttpdResource::pendingRequest,[=](LSHttpdRequest* request){
        request->response404();
    });
    auto res204 = h->registerResource(QRegularExpression("^/noContent$"));
    QObject::connect(res204.data(),&LSHttpdResource::pendingRequest,[=](LSHttpdRequest* request){
        request->response204();
    });
    auto res301 = h->registerResource(QRegularExpression("^/movedPerm$"));
    QObject::connect(res301.data(),&LSHttpdResource::pendingRequest,[=](LSHttpdRequest* request){
        request->response301("404.html");
    });
    auto resCustom = h->registerResource(QRegularExpression("^/index.html$"));
    QObject::connect(resCustom.data(),&LSHttpdResource::pendingRequest,[=](LSHttpdRequest* request){
        QFile file("index.html");
        if(file.exists())
        {
            if(file.open(QIODevice::ReadOnly))
            {
                QByteArray data = file.readAll();
                static QUuid nonceId = QUuid::createUuid();
                QList<LSHttpdHeaderPair> list;

                bool authActive = false;
                for(auto it = request->requestHeaderList().constBegin(), et=request->requestHeaderList().constEnd(); it!=et; ++it)
                {
                    if(it->first == "Authorization")
                    {
                        QByteArray calc = request->calculateDigestMD5("admin","admin","UniBaseDaemon",nonceId.toByteArray().toBase64());
                        if(calc == request->extractDigest(it->second.toLatin1()))
                        {
                            authActive = true;
                        }
                        break;
                    }
                }
                if(!authActive)
                {
                    LSHttpdHeaderPair auth;
                    nonceId == QUuid::createUuid();
                    auth.first = "WWW-Authenticate";
                    auth.second = "Digest realm=\"UniBaseDaemon\",nonce=\""+nonceId.toByteArray().toBase64()+"\"";
                    list.append(auth);

                    request->createResponse(LSHttpdRequest::AuthRequired,list,data);
                }
                else
                {
                    LSHttpdHeaderPair contentType;
                    contentType.first = "Content-Type";
                    contentType.second = "text/html; charset=UTF-8";
                    list.append(contentType);

                    LSHttpdHeaderPair setCookie;
                    setCookie.first = "Set-Cookie";
                    setCookie.second = "User=08164712";
                    list.append(setCookie);

                    request->createResponse(LSHttpdRequest::OK,list,data);
                }
                request->sendResponse();
                file.close();
            }
        }
    });

    return a.exec();
}
