#include "lshttpdprivate.h"
#include "lshttpd.h"

#include <QSslConfiguration>
#include <QFile>

#include <lshttpdresource.h>

static QMap<http_parser*,LSHttpdRequest*> LSHTTPD_PARSER_MAP;

LSHttpdPrivate::LSHttpdPrivate(QHostAddress address, quint16 port, bool useSSL, LSHttpd *q) : QTcpServer(q), q_ptr(q)
{
    listen(address,port);
}

LSHttpdPrivate::~LSHttpdPrivate()
{
    LSHTTPD_PARSER_MAP.clear();
    qDeleteAll(m_openRequests);
    m_openRequests.clear();
}

void LSHttpdPrivate::setCertificate(const QString &path, QSsl::EncodingFormat format)
{
    QList<QSslCertificate> list = QSslCertificate::fromPath(path,format);
    for(auto it = list.constBegin(), et = list.constEnd(); it!=et; ++it)
    {
        if(!it->isNull())
        {
            m_sslCert = (*it);
            return;
        }
    }
}

void LSHttpdPrivate::setCertificate(const QSslCertificate &certificate)
{
    m_sslCert = certificate;
}

void LSHttpdPrivate::setPrivateKey(const QString &path, QSsl::KeyAlgorithm keyAlgorithm, QSsl::EncodingFormat format, const QByteArray &passPhrase)
{
    QFile file(path);
    if(file.exists() && file.open(QIODevice::ReadOnly))
    {
        QSslKey key = QSslKey(&file,keyAlgorithm,format,QSsl::PrivateKey,passPhrase);
        if(!key.isNull())
        {
            m_sslKey = key;
        }
        file.close();
    }
}

void LSHttpdPrivate::setPrivateKey(const QSslKey &key)
{
    m_sslKey = key;
}

QSharedPointer<LSHttpdResource> LSHttpdPrivate::registerFallback()
{
    QRegularExpression rx(".*");
    if(!m_fallBackResource.isNull())
    {
        m_fallBackResource->invalidate();
    }
    m_fallBackResource.reset(new LSHttpdResource());
    m_fallBackResource->setResourceIdentifier(rx);
    return m_fallBackResource;
}

void LSHttpdPrivate::unregisterFallback()
{
    if(!m_fallBackResource.isNull())
    {
        m_fallBackResource->invalidate();
    }
    m_fallBackResource.reset();
}

QSharedPointer<LSHttpdResource> LSHttpdPrivate::registerResource(QRegularExpression rx)
{
    for(auto it = m_registeredResources.constBegin(), et =m_registeredResources.constEnd(); it!=et; ++it)
    {
        if (it->data()->resourceIdentifier() == rx)
        {
            return (*it);
        }
    }
    auto res = QSharedPointer<LSHttpdResource>(new LSHttpdResource());
    res->setResourceIdentifier(rx);
    m_registeredResources.append(res);
    return res;
}

void LSHttpdPrivate::unregisterResource(QSharedPointer<LSHttpdResource> resource)
{
    Q_ASSERT(resource.data());
    m_registeredResources.removeOne(resource);
    resource->invalidate();
}

void LSHttpdPrivate::incomingConnection(qintptr handle)
{
    QSslSocket* s = new QSslSocket;
    s->setSslConfiguration(QSslConfiguration::defaultConfiguration());
    s->setLocalCertificate(m_sslCert);
    s->setPrivateKey(m_sslKey);
    if(Q_LIKELY(s->setSocketDescriptor(handle)))
    {
        LSHttpdRequest *request = new LSHttpdRequest(s);
        LSHTTPD_PARSER_MAP.insert(request->d_ptr->requestParser(),request);
        m_openRequests.append(request);
        connect(request,&LSHttpdRequest::requestFinished,this,&LSHttpdPrivate::removeRequest);
        connect(request->d_ptr,&LSHttpdRequestPrivate::requestCompleted,this,&LSHttpdPrivate::mapRequestToResource);
    }else{
        delete s;
    }
}

void LSHttpdPrivate::removeRequest()
{
    LSHttpdRequest *request = static_cast<LSHttpdRequest*>(sender());
    LSHTTPD_PARSER_MAP.remove(request->d_ptr->requestParser());
    m_openRequests.removeOne(request);
    request->deleteLater();
}

void LSHttpdPrivate::mapRequestToResource(LSHttpdRequest *request)
{
    if(!m_openRequests.contains(request))
    {
        return;
    }
    for(auto it = m_registeredResources.constBegin(), et = m_registeredResources.constEnd(); it!=et; ++it)
    {
        if(it->data()->resourceIdentifier().match(request->resource()).hasMatch())
        {
            it->data()->promoteRequest(request);
            return;
        }
    }
    if(!m_fallBackResource.isNull())
    {
        m_fallBackResource->promoteRequest(request);
    }
}

bool LSHttpdRequestPrivate::requestComplete() const
{
    return m_requestComplete;
}

bool LSHttpdRequestPrivate::responseComplete() const
{
    return m_responseComplete;
}

int LSHttpdRequestPrivate::onNotificationNull(http_parser *p)
{
    qDebug()<<"Notify";
    return 0;
}

int LSHttpdRequestPrivate::onDataNull(http_parser *p, const char *at, size_t length)
{
    qDebug()<<"Data:"<<QByteArray(at,length);
    return 0;
}

int LSHttpdRequestPrivate::onRequestMessageCompleteWrapper(http_parser *parser)
{
    if(LSHTTPD_PARSER_MAP.contains(parser))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(parser);
        Q_ASSERT(r);

        return r->d_ptr->onRequestMessageComplete();
    }
    return -1;
}

int LSHttpdRequestPrivate::onRequestMessageComplete()
{
    m_requestComplete = true;
    emit requestCompleted(q_ptr);

    //TODO Response hier ausgeben und verarbeiten

    //Verarbeiten der Anfrage
    //socket->write("HTTP/1.1 404 Not Found\r\n\r\n");
    //socket->write("HTTP/1.1 200\r\n<html><head><Title>Test</title></head><body><b>test</b></body></html>\r\n\r\n");
    return 0;
}

QByteArray LSHttpdRequestPrivate::requestRaw()
{
    return m_requestData;
}

void LSHttpdRequestPrivate::response404()
{
    QByteArray ba = "HTTP/1.1 404 Not Found\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 102\r\n"
                    "\r\n"
                    "<!DOCTYPE html><html lang=en><title>Error 404 (Not Found)!!1</title>You should not read this...</html>";
    m_socket->write(ba);
    m_socket->waitForBytesWritten();
}

void LSHttpdRequestPrivate::onSocketReadyRead()
{
    m_requestData.append(m_socket->readAll());

    //Parser for request data
    http_parser_execute(&m_requestParser,&m_requestParserSettings,m_requestData.data(),m_requestData.size());
}

void LSHttpdRequestPrivate::closeSocket()
{
    m_socket->disconnect();
    m_socket->disconnectFromHost();
}

void LSHttpdRequestPrivate::closeRequest()
{
    if (m_socket->state() == QAbstractSocket::ConnectedState || m_socket->state() == QAbstractSocket::ConnectingState)
    {
        closeSocket();
    }
    q_ptr->closeRequest();
}

LSHttpdRequestPrivate::LSHttpdRequestPrivate(LSHttpdRequest *ptr, QSslSocket *socket) : QObject(ptr), q_ptr(ptr)
{
    Q_ASSERT(socket);
    m_socket.reset(socket);
    m_requestComplete = false;
    m_responseComplete = false;

    m_requestParserSettings.on_message_begin = onNotificationNull;
    m_requestParserSettings.on_header_field = onDataNull;
    m_requestParserSettings.on_header_value = onDataNull;
    m_requestParserSettings.on_url = onDataNull;
    m_requestParserSettings.on_body = onDataNull;
    m_requestParserSettings.on_status = onDataNull;
    m_requestParserSettings.on_chunk_complete = onNotificationNull;
    m_requestParserSettings.on_chunk_header = onNotificationNull;
    m_requestParserSettings.on_headers_complete = onNotificationNull;
    m_requestParserSettings.on_message_complete = onRequestMessageCompleteWrapper;

    m_responseParserSettings.on_message_begin = onNotificationNull;
    m_responseParserSettings.on_header_field = onDataNull;
    m_responseParserSettings.on_header_value = onDataNull;
    m_responseParserSettings.on_url = onDataNull;
    m_responseParserSettings.on_body = onDataNull;
    m_responseParserSettings.on_status = onDataNull;
    m_responseParserSettings.on_chunk_complete = onNotificationNull;
    m_responseParserSettings.on_chunk_header = onNotificationNull;
    m_responseParserSettings.on_headers_complete = onNotificationNull;
    m_responseParserSettings.on_message_complete = onNotificationNull;

    http_parser_init(&m_requestParser, HTTP_REQUEST);
    http_parser_init(&m_responseParser, HTTP_RESPONSE);


    connect(socket,&QSslSocket::encrypted, this, [=](){
        connect(socket,&QSslSocket::readyRead,this,&LSHttpdRequestPrivate::onSocketReadyRead);
    });

    //TODO Currently we ignore SSL Errors
    connect(socket,static_cast<void (QSslSocket::*)(const QList<QSslError> &)>(&QSslSocket::sslErrors),this,[=](){
        qDebug()<<"Socket SSLErrors:"<<socket->sslErrors();
        socket->ignoreSslErrors();
    });

    //Error in Socket => close socket and request
    connect(socket,static_cast<void (QSslSocket::*)(QAbstractSocket::SocketError)>(&QSslSocket::error),this,[=](){
        qDebug()<<"Socket Error:"<<socket->error();
        closeRequest();
    });

    //Client disconnects before request is finished => just close request
    connect(socket,&QSslSocket::disconnected,this,&LSHttpdRequestPrivate::closeRequest);

    socket->startServerEncryption();
}

LSHttpdRequestPrivate::~LSHttpdRequestPrivate()
{
    closeSocket();
}

http_parser *LSHttpdRequestPrivate::requestParser()
{
    return &m_requestParser;
}

http_parser_settings *LSHttpdRequestPrivate::requestParserSettings()
{
    return &m_requestParserSettings;
}

http_parser *LSHttpdRequestPrivate::responseParser()
{
    return &m_responseParser;
}

http_parser_settings *LSHttpdRequestPrivate::responseParserSettings()
{
    return &m_responseParserSettings;
}

bool LSHttpdRequestPrivate::validateResponse(QByteArray outData)
{
    Q_UNIMPLEMENTED();
    return true;
}

bool LSHttpdRequestPrivate::validateResponse()
{
    Q_UNIMPLEMENTED();
    return true;
}
