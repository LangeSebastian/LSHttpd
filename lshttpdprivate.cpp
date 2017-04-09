#include "lshttpdprivate.h"

#include <QDebug>
#include <QSslConfiguration>
#include <QFile>
#include <QStringList>
#include <QNetworkInterface>
#include <QNetworkAddressEntry>
#include <QNetworkSession>
#include <QMetaMethod>

#include <lshttpd.h>
#include <lshttpdresource.h>

static QMap<http_parser*,LSHttpdRequest*> LSHTTPD_PARSER_MAP;

LSHttpdPrivate::LSHttpdPrivate(QHostAddress address, quint16 port, bool useSSL, LSHttpd *q) : QTcpServer(q), q_ptr(q), m_useSSL(useSSL)
{
    m_ncm.reset(new QNetworkConfigurationManager());
    m_hostAddress = address;
    m_port = port;

    connect(m_ncm.data(),&QNetworkConfigurationManager::configurationAdded,this,&LSHttpdPrivate::networkConfigurationChanged);
    connect(m_ncm.data(),&QNetworkConfigurationManager::configurationChanged,this,&LSHttpdPrivate::networkConfigurationChanged);
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
#if (QT_VERSION < QT_VERSION_CHECK(5,5,0))
    m_registeredResources.takeAt(m_registeredResources.indexOf(resource));
#else
    m_registeredResources.removeOne(resource);
#endif
    resource->invalidate();
}

void LSHttpdPrivate::networkConfigurationChanged(const QNetworkConfiguration &inConfig)
{
    if(inConfig.state() == QNetworkConfiguration::Active)
    {
        if(inConfig.type() != QNetworkConfiguration::Invalid)
        {
            QNetworkSession *ns = new QNetworkSession(inConfig);
            QNetworkInterface ni = ns->interface();
            QList<QNetworkAddressEntry> nl = ni.addressEntries();

            for(auto it=nl.constBegin(), et=nl.constEnd();it!=et;++it)
            {

                if(m_hostAddress == QHostAddress::Any)
                {
                    if((*it).ip().protocol()==QAbstractSocket::AnyIPProtocol
                            || (*it).ip().protocol()==QAbstractSocket::IPv4Protocol
                            || (*it).ip().protocol()==QAbstractSocket::IPv6Protocol)
                    {
                        listen((*it).ip(),m_port);
                    }
                }
                else
                {
                    if((*it).ip() == m_hostAddress)
                    {
                        listen(m_hostAddress,m_port);
                    }
                }
            }
            delete ns;
        }
    }
}

void LSHttpdPrivate::incomingConnection(qintptr handle)
{
    QTcpSocket *socket;
    if(m_useSSL)
    {
        QSslSocket* s = new QSslSocket;
        s->setSslConfiguration(QSslConfiguration::defaultConfiguration());
        s->setLocalCertificate(m_sslCert);
        s->setPrivateKey(m_sslKey);
        socket = s;
    }
    else
    {
        socket = new QTcpSocket;
    }
    if(Q_LIKELY(socket->setSocketDescriptor(handle)))
    {
        LSHttpdRequest *request = new LSHttpdRequest(socket);
        LSHTTPD_PARSER_MAP.insert(request->d_ptr->requestParser(),request);
        LSHTTPD_PARSER_MAP.insert(request->d_ptr->responseParser(),request);
        m_openRequests.append(request);
        connect(request,&LSHttpdRequest::requestFinished,this,&LSHttpdPrivate::removeRequest);
        connect(request->d_ptr,&LSHttpdRequestPrivate::requestCompleted,this,&LSHttpdPrivate::mapRequestToResource);
    }else{
        delete socket;
    }
}

void LSHttpdPrivate::removeRequest()
{
    LSHttpdRequest *request = static_cast<LSHttpdRequest*>(sender());
    LSHTTPD_PARSER_MAP.remove(request->d_ptr->requestParser());
    LSHTTPD_PARSER_MAP.remove(request->d_ptr->responseParser());
#if (QT_VERSION < QT_VERSION_CHECK(5,5,0))
    m_openRequests.takeAt(m_openRequests.indexOf(request));
#else
    m_openRequests.removeOne(request);
#endif
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
    if(m_fallBackResource.isNull())
    {
        request->response404();
    }else{
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
    Q_UNUSED(p);
#ifdef LSHTTPD_DEBUG
    qDebug()<<"Notify";
#endif
    return 0;
}

int LSHttpdRequestPrivate::onDataNull(http_parser *p, const char *at, size_t length)
{
    Q_UNUSED(p);
#ifdef LSHTTPD_DEBUG
    qDebug()<<"Data:"<<QByteArray(at,length);
#else
    Q_UNUSED(at);
    Q_UNUSED(length);
#endif
    return 0;
}

int LSHttpdRequestPrivate::onMessageBeginCB(http_parser *parser)
{
    if(LSHTTPD_PARSER_MAP.contains(parser))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(parser);
        Q_ASSERT(r);

        return r->d_ptr->onMessageBegin(parser);
    }
    return -1;
}

int LSHttpdRequestPrivate::onMessageBegin(http_parser *p)
{
#ifdef LSHTTPD_DEBUG
    qDebug()<<Q_FUNC_INFO<<"Parser: "<<(p==&m_requestParser?"Request: ":"Response: ");
#endif
    if (p == &m_requestParser)
    {
        m_requestComplete = false;
    }
    else
    {
        m_responseComplete = false;
    }
    return 0;
}

int LSHttpdRequestPrivate::onUrlCB(http_parser *p, const char *at, size_t length)
{
    if(LSHTTPD_PARSER_MAP.contains(p))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(p);
        Q_ASSERT(r);

        return r->d_ptr->onUrl(QByteArray(at,length),p);
    }
    return -1;
}

int LSHttpdRequestPrivate::onUrl(QByteArray in, http_parser *p)
{
#ifdef LSHTTPD_DEBUG
    qDebug()<<Q_FUNC_INFO<<"Parser: "<<(p==&m_requestParser?"Request: ":"Response: ")<<in;
#endif
    if (p == &m_requestParser)
    {
        m_requestParserState = STATE_URL;
        q_ptr->m_resource.append(QString::fromLocal8Bit(in));
    }
    else
    {
        m_responseParserState = STATE_URL;
        qDebug()<<Q_FUNC_INFO<<"Response should not have url.";
    }
    return 0;
}

int LSHttpdRequestPrivate::onStatusCB(http_parser *p, const char *at, size_t length)
{
    if(LSHTTPD_PARSER_MAP.contains(p))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(p);
        Q_ASSERT(r);

        return r->d_ptr->onStatus(QByteArray(at,length),p);
    }
    return -1;
}

int LSHttpdRequestPrivate::onStatus(QByteArray in, http_parser *p)
{
#ifdef LSHTTPD_DEBUG
    qDebug()<<Q_FUNC_INFO<<"Parser: "<<(p==&m_requestParser?"Request: ":"Response: ")<<in;
#endif
    if (p == &m_requestParser)
    {
        m_requestParserState = STATE_STATUS;
        qDebug()<<Q_FUNC_INFO<<"Request should not have statuscode.";
    }
    else
    {
        m_responseParserState = STATE_STATUS;

        q_ptr->m_responseCode = in.toInt();
    }
    return 0;
}

int LSHttpdRequestPrivate::onHeaderFieldCB(http_parser *p, const char *at, size_t length)
{
    if(LSHTTPD_PARSER_MAP.contains(p))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(p);
        Q_ASSERT(r);

        return r->d_ptr->onHeaderField(QByteArray(at,length),p);
    }
    return -1;
}

int LSHttpdRequestPrivate::onHeaderField(QByteArray in, http_parser *p)
{
#ifdef LSHTTPD_DEBUG
    qDebug()<<Q_FUNC_INFO<<"Parser: "<<(p==&m_requestParser?"Request: ":"Response: ")<<in;
#endif
    if (p == &m_requestParser)
    {
        if (m_requestParserState != STATE_HEADERFIELD)
        {
            q_ptr->m_requestHeaderList.append(LSHttpdHeaderPair());
        }
        m_requestParserState = STATE_HEADERFIELD;
        q_ptr->m_requestHeaderList.last().first.append(in);
    }
    else
    {
        if (m_responseParserState != STATE_HEADERFIELD)
        {
            q_ptr->m_responseHeaderList.append(LSHttpdHeaderPair());
        }
        m_responseParserState = STATE_HEADERFIELD;
        q_ptr->m_responseHeaderList.last().first.append(in);
    }
    return 0;
}

int LSHttpdRequestPrivate::onHeaderValueCB(http_parser *p, const char *at, size_t length)
{
    if(LSHTTPD_PARSER_MAP.contains(p))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(p);
        Q_ASSERT(r);

        return r->d_ptr->onHeaderValue(QByteArray(at,length),p);
    }
    return -1;
}

int LSHttpdRequestPrivate::onHeaderValue(QByteArray in, http_parser *p)
{
#ifdef LSHTTPD_DEBUG
    qDebug()<<Q_FUNC_INFO<<"Parser: "<<(p==&m_requestParser?"Request: ":"Response: ")<<in;
#endif
    if (p == &m_requestParser)
    {
        m_requestParserState = STATE_HEADERVALUE;
        q_ptr->m_requestHeaderList.last().second.append(in);
    }
    else
    {
        m_responseParserState = STATE_HEADERVALUE;
        q_ptr->m_responseHeaderList.last().second.append(in);
    }
    return 0;
}

int LSHttpdRequestPrivate::onHeaderCompleteCB(http_parser *p)
{
    if(LSHTTPD_PARSER_MAP.contains(p))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(p);
        Q_ASSERT(r);

        return r->d_ptr->onHeaderComplete(p);
    }
    return -1;

}

int LSHttpdRequestPrivate::onHeaderComplete(http_parser *p)
{
    Q_UNUSED(p);
    //NOTE: Nothing to do on header complete?
    return 0;
}

int LSHttpdRequestPrivate::onBodyCB(http_parser *p, const char *at, size_t length)
{
    if(LSHTTPD_PARSER_MAP.contains(p))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(p);
        Q_ASSERT(r);

        return r->d_ptr->onBody(QByteArray(at,length),p);
    }
    return -1;
}

int LSHttpdRequestPrivate::onBody(QByteArray in, http_parser *p)
{
#ifdef LSHTTPD_DEBUG
    qDebug()<<Q_FUNC_INFO<<"Parser: "<<(p==&m_requestParser?"Request: ":"Response: ")<<in;
#endif
    if (p == &m_requestParser)
    {
        m_requestParserState = STATE_BODY;
        q_ptr->m_requestBodyData.append(in);
    }
    else
    {
        m_responseParserState = STATE_BODY;
        q_ptr->m_responseBodyData.append(in);
    }
    return 0;
}

int LSHttpdRequestPrivate::onMessageCompleteWrapperCB(http_parser *parser)
{
    if(LSHTTPD_PARSER_MAP.contains(parser))
    {
        LSHttpdRequest *r = LSHTTPD_PARSER_MAP.value(parser);
        Q_ASSERT(r);

        return r->d_ptr->onMessageComplete(parser);
    }
    return -1;
}

int LSHttpdRequestPrivate::onMessageComplete(http_parser *p)
{
#ifdef LSHTTPD_DEBUG
    qDebug()<<Q_FUNC_INFO<<"Parser: "<<(p==&m_requestParser?"Request: ":"Response: ");
#endif
    if (p == &m_requestParser)
    {
#ifdef LSHTTPD_DEBUG
        qDebug()<<Q_FUNC_INFO<<"Error: "<<p->http_errno;
#endif
        q_ptr->m_method = parserMethodToString(p->method);
        q_ptr->m_methodId = parserMethodToEnum(p->method);
        m_requestComplete = true;
        emit requestCompleted(q_ptr);
    }
    else
    {
        m_responseComplete = true;
        emit responseCompleted(q_ptr);
    }
    return 0;
}

QByteArray LSHttpdRequestPrivate::requestRaw()
{
    return m_requestData;
}

QByteArray LSHttpdRequestPrivate::responseRaw()
{
    return m_responseData;
}

void LSHttpdRequestPrivate::response200()
{
    QByteArray ba = "HTTP/1.1 204 No Content\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response204()
{
    QByteArray ba = "HTTP/1.1 204 No Content\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response301(QByteArray redirectLocation)
{
    QByteArray ba = "HTTP/1.1 301 Moved Permanently\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Location: "+redirectLocation+"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response302(QByteArray redirectLocation)
{
    QByteArray ba = "HTTP/1.1 302 Found\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Location: "+redirectLocation+"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response303(QByteArray redirectLocation)
{
    QByteArray ba = "HTTP/1.1 303 See Other\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Location: "+redirectLocation+"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response304(QDateTime modificationDate)
{
    QByteArray ba = "HTTP/1.1 304 Not Modified\r\n"
                    "Date: "+modificationDate.toString(Qt::ISODate).toLatin1()+"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response307(QByteArray redirectLocation)
{
    QByteArray ba = "HTTP/1.1 307 Temporary Redirect\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Location: "+redirectLocation+"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response400()
{
    QByteArray ba = "HTTP/1.1 400 Bad Request\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 165\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>400 Bad Request</title>\r\n</head>\r\n<body>\r\n<h1>Bad Request</h1>\r\n<p>Your Browser sent an invalid request.</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response401Basic(QByteArray realm)
{
    QByteArray ba = "HTTP/1.1 401 Unauthorized\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "WWW-Authenticate: realm=\""+realm+"\"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response401Digest(QByteArray realm, QByteArray nonce)
{
    QByteArray ba = "HTTP/1.1 401 Unauthorized\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "WWW-Authenticate: Digest realm=\""+realm+"\", nonce=\""+nonce.toBase64()+"\"\r\n"
                    "\r\n";
    writeData(ba);
}

void LSHttpdRequestPrivate::response403()
{
    QByteArray ba = "HTTP/1.1 403 Forbidden\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 170\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>403 Forbidden</title>\r\n</head>\r\n<body>\r\n<h1>Forbidden</h1>\r\n<p>Access to the requested resource is forbidden.</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response404()
{
    QByteArray content = "<html>\r\n<head>\r\n<title>404 Document not found</title>\r\n</head>\r\n<body>\r\n<h1>Document not found</h1>\r\n<p>The requested resource does not exist on this server</p>\r\n</body>\r\n</html>";
    QByteArray ba = "HTTP/1.1 404 Not Found\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: ";
    ba.append(QString::number(content.size()).toLatin1());
    ba.append("\r\n\r\n");
    ba.append(content);

    writeData(ba);
}

void LSHttpdRequestPrivate::response405(QStringList allowedMethods)
{
    if(allowedMethods.isEmpty())
    {
        response400();
        return;
    }
    QByteArray methods;
    methods.append(allowedMethods.takeFirst().toLatin1());
    foreach(const QString method, allowedMethods)
    {
        methods.append(", "+method.toLatin1());
    }
    QByteArray ba = "HTTP/1.1 405 Method not allowed\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Allow: "+methods+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 201\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>405 Method not allowed</title>\r\n</head>\r\n<body>\r\n<h1>Method not allowed</h1>\r\n<p>The method for your request is not allowed on this resource</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response410()
{
    QByteArray ba = "HTTP/1.1 410 Gone\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 194\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>410 Gone</title>\r\n</head>\r\n<body>\r\n<h1>Gone</h1>\r\n<p>The requested resource has been permanently removed.</p>\r\n<p>Please remove all bookmarks and links for this resource</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response411()
{
    QByteArray ba = "HTTP/1.1 411 Length Required\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 217\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>411 Length required</title>\r\n</head>\r\n<body>\r\n<h1>Length required</h1>\r\n<p>The request did not contain a 'Content-Length' header, though this is a mandatory</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response412()
{
    QByteArray ba = "HTTP/1.1 412 Precondition failed\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 183\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>412 Precondition failed</title>\r\n</head>\r\n<body>\r\n<h1>Precondition failed</h1>\r\n<p>A precondition for this request failed.</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response500()
{
    QByteArray ba = "HTTP/1.1 500 Server Error\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 162\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>500 Server Error</title>\r\n</head>\r\n<body>\r\n<h1>Server Error</h1>\r\n<p>The server encountered an error.</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response501()
{
    QByteArray ba = "HTTP/1.1 501 Not Implemented\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 185\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>501 Not implemented</title>\r\n</head>\r\n<body>\r\n<h1>Not implemented</h1>\r\n<p>The requested operation is not (yet) implemented.</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response502()
{
    QByteArray ba = "HTTP/1.1 502 Bad Gateway\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 172\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>502 Bad Gateway</title>\r\n</head>\r\n<body>\r\n<h1>Bad Gateway</h1>\r\n<p>Unexpected result on forwarding the request.</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response503()
{
    QByteArray ba = "HTTP/1.1 503 Service Unavailable\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 204\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>503 Service Unavailable</title>\r\n</head>\r\n<body>\r\n<h1>Service unavailable</h1>\r\n<p>The service is currently unavailable, please try again later</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::response504()
{
    QByteArray ba = "HTTP/1.1 504 Gateway Timeout\r\n"
                    "Date: "+QDateTime::currentDateTime().toString(Qt::ISODate).toLatin1()+"\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: 194\r\n"
                    "\r\n"
                    "<html>\r\n<head>\r\n<title>504 Gateway Timeout</title>\r\n</head>\r\n<body>\r\n<h1>Gateway Timeout</h1>\r\n<p>The server received a timeout upon forwarding the request.</p>\r\n</body>\r\n</html>";
    writeData(ba);
}

void LSHttpdRequestPrivate::onSocketReadyRead()
{
    QByteArray newData = m_socket->readAll();
    m_requestData.append(newData);

    //Parser for request data
    http_parser_execute(&m_requestParser,&m_requestParserSettings,newData.constData(),newData.size());
}

void LSHttpdRequestPrivate::bytesWritten(qint64 bytes)
{
    m_responseBytesLeftToWrite = m_responseBytesLeftToWrite - bytes;
    if(m_responseBytesLeftToWrite <= 0)
    {
        closeRequest();
    }
}

void LSHttpdRequestPrivate::writeData(QByteArray ba)
{
    m_responseBytesLeftToWrite += ba.size();
    QMetaObject::invokeMethod(this,"writeDataSocket",Qt::QueuedConnection,Q_ARG(QByteArray,ba));
}

void LSHttpdRequestPrivate::writeDataSocket(QByteArray ba)
{
    if(m_socket->isOpen() && m_socket->state() == QAbstractSocket::ConnectedState)
    {
        m_socket->write(ba);
        m_socket->flush();
    }
    else
    {
        m_responseBytesLeftToWrite -= ba.size();
        if(m_responseBytesLeftToWrite <= 0)
        {
            closeRequest();
        }
    }
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

QString LSHttpdRequestPrivate::parserMethodToString(int method)
{
    switch(method)
    {
#define XX(num, name, string) case num: return QStringLiteral(#string);
        HTTP_METHOD_MAP(XX)
#undef XX
    }
    return QString();
}

LSHttpdRequest::RequestMethod LSHttpdRequestPrivate::parserMethodToEnum(int method)
{
    switch (method) {
        case HTTP_GET:
            return LSHttpdRequest::GET;
            break;
        case HTTP_HEAD:
            return LSHttpdRequest::HEAD;
            break;
        case HTTP_POST:
            return LSHttpdRequest::POST;
            break;
        case HTTP_PUT:
            return LSHttpdRequest::PUT;
            break;
        case HTTP_DELETE:
            return LSHttpdRequest::DELETE;
            break;
        default:
            return LSHttpdRequest::OTHER;
            break;
    }
}

LSHttpdRequestPrivate::LSHttpdRequestPrivate(LSHttpdRequest *ptr, QTcpSocket* socket) : QObject(ptr), q_ptr(ptr)
{
    Q_ASSERT(socket);
    m_socket.reset(socket);

    m_requestComplete = false;
    m_responseComplete = false;
    m_responseBytesLeftToWrite = 0;

    m_requestParserState = STATE_NULL;
    m_responseParserState = STATE_NULL;

    m_requestParserSettings.on_message_begin = onNotificationNull;
    m_requestParserSettings.on_status = onDataNull;
    m_requestParserSettings.on_url = onUrlCB;
    m_requestParserSettings.on_header_field = onHeaderFieldCB;
    m_requestParserSettings.on_header_value = onHeaderValueCB;
    m_requestParserSettings.on_chunk_complete = onNotificationNull;
    m_requestParserSettings.on_chunk_header = onNotificationNull;
    m_requestParserSettings.on_headers_complete = onHeaderCompleteCB;
    m_requestParserSettings.on_body = onBodyCB;
    m_requestParserSettings.on_message_complete = onMessageCompleteWrapperCB;

    m_responseParserSettings.on_message_begin = onNotificationNull;
    m_responseParserSettings.on_status = onStatusCB;
    m_responseParserSettings.on_url = onDataNull;
    m_responseParserSettings.on_header_field = onHeaderFieldCB;
    m_responseParserSettings.on_header_value = onHeaderValueCB;
    m_responseParserSettings.on_chunk_complete = onNotificationNull;
    m_responseParserSettings.on_chunk_header = onNotificationNull;
    m_responseParserSettings.on_headers_complete = onHeaderCompleteCB;
    m_responseParserSettings.on_body = onBodyCB;
    m_responseParserSettings.on_message_complete = onMessageCompleteWrapperCB;

    http_parser_init(&m_requestParser, HTTP_REQUEST);
    http_parser_init(&m_responseParser, HTTP_RESPONSE);

    QSslSocket* sslSocket = qobject_cast<QSslSocket*>(socket);
    if(sslSocket != Q_NULLPTR)
    {
#ifdef LSHTTPD_DEBUG
        qDebug()<<"Socket is SSL Socket";
#endif
        connect(sslSocket,&QSslSocket::encrypted, this, [=](){
            connect(sslSocket,&QSslSocket::readyRead,this,&LSHttpdRequestPrivate::onSocketReadyRead);
        });

        //TODO Currently we ignore SSL Errors
        connect(sslSocket,static_cast<void (QSslSocket::*)(const QList<QSslError> &)>(&QSslSocket::sslErrors),this,[=](){
            qDebug()<<"Socket SSLErrors:"<<static_cast<QSslSocket*>(socket)->sslErrors();
            sslSocket->ignoreSslErrors();
        });

        //Error in Socket => close socket and request
        connect(sslSocket,static_cast<void (QSslSocket::*)(QAbstractSocket::SocketError)>(&QSslSocket::error),this,[=](){
            if(!isSignalConnected(QMetaMethod::fromSignal(&LSHttpdRequestPrivate::requestCompleted)))
            {
                qDebug()<<Q_FUNC_INFO<<"Socket Error:"<<socket->errorString()<<"("<<socket->error()<<")";
                closeRequest();
            }
        });

        connect(socket,&QSslSocket::bytesWritten,this,&LSHttpdRequestPrivate::bytesWritten);
        sslSocket->startServerEncryption();
    }
    else
    {
#ifdef LSHTTPD_DEBUG
        qDebug()<<"Socket is TCP Socket";
#endif
        connect(socket,&QTcpSocket::readyRead,this,&LSHttpdRequestPrivate::onSocketReadyRead);
        //Error in Socket => close socket and request
        connect(socket,static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>(&QTcpSocket::error),this,[=](){
            if(!isSignalConnected(QMetaMethod::fromSignal(&LSHttpdRequestPrivate::requestCompleted)))
            {
                qDebug()<<Q_FUNC_INFO<<"Socket Error:"<<socket->errorString()<<"("<<socket->error()<<")";
                closeRequest();
            }
        });
        connect(socket,&QTcpSocket::bytesWritten,this,&LSHttpdRequestPrivate::bytesWritten);
        if(socket->bytesAvailable())
        {
            QMetaObject::invokeMethod(this,"onSocketReadyRead");
        }
    }
}

LSHttpdRequestPrivate::~LSHttpdRequestPrivate()
{
    closeSocket();
}

QHostAddress LSHttpdRequestPrivate::remoteHost()
{
    if (!m_socket.isNull())
    {
        return m_socket->peerAddress();
    }
    return QHostAddress();
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

void LSHttpdRequestPrivate::createResponse(int in_status, QList<LSHttpdHeaderPair> in_headerList, QByteArray in_bodyData)
{
    m_responseData.clear();
    m_responseData.append(QString("HTTP/1.1 %1\r\n").arg(in_status));
    bool hasContentLength = false;
    bool hasDate = false;
    for(auto it = in_headerList.constBegin(), et = in_headerList.constEnd(); it!=et; ++it)
    {
        m_responseData.append(it->first).append(": ").append(it->second).append("\r\n");
        if(Q_UNLIKELY(it->first.compare("Content-Length",Qt::CaseInsensitive) == 0))
        {
            hasContentLength = true;
        }
        if(Q_UNLIKELY(it->first.compare("Date",Qt::CaseInsensitive) == 0))
        {
            hasDate = true;
        }
    }
    if(!hasContentLength)
    {
        m_responseData.append(QString("Content-Length: %1\r\n").arg(in_bodyData.size()));
    }
    if(!hasDate)
    {
        m_responseData.append(QString("Date: %1\r\n").arg(QDateTime::currentDateTime().toString(Qt::ISODate)));
    }

    m_responseData.append("\r\n");
    m_responseData.append(in_bodyData);
}

bool LSHttpdRequestPrivate::validateResponse(QByteArray outData)
{
    m_responseData = outData;
    m_responseParserState = STATE_NULL;
    http_parser_execute(&m_responseParser,&m_responseParserSettings,m_responseData.data(),m_responseData.size());

    return m_responseComplete;
}

bool LSHttpdRequestPrivate::validateResponse()
{
    m_responseParserState = STATE_NULL;
    http_parser_execute(&m_responseParser,&m_responseParserSettings,m_responseData.data(),m_responseData.size());

    return m_responseComplete;
}

bool LSHttpdRequestPrivate::sendResponse()
{
    if(!m_responseComplete)
    {
        if(!validateResponse())
        {
            return false;
        }
    }
    writeData(m_responseData);
    return true;
}
