#include "lshttpd.h"
#include "lshttpdprivate.h"

LSHttpd::LSHttpd(QHostAddress address, quint16 port, bool useSSL) : d_ptr(new LSHttpdPrivate(address, port, useSSL, this))
{

}

void LSHttpd::setCertificate(const QString &path, QSsl::EncodingFormat format)
{
    d_ptr->setCertificate(path,format);
}

void LSHttpd::setCertificate(const QSslCertificate &certificate)
{
    d_ptr->setCertificate(certificate);
}

void LSHttpd::setPrivateKey(const QString &path, QSsl::KeyAlgorithm keyAlgorithm, QSsl::EncodingFormat format, const QByteArray &passPhrase)
{
    d_ptr->setPrivateKey(path, keyAlgorithm, format, passPhrase);
}

void LSHttpd::setPrivateKey(const QSslKey &key)
{
    d_ptr->setPrivateKey(key);
}

QSharedPointer<LSHttpdResource> LSHttpd::registerFallback()
{
    return d_ptr->registerFallback();
}

void LSHttpd::unregisterFallback()
{
    d_ptr->unregisterFallback();
}

QSharedPointer<LSHttpdResource> LSHttpd::registerResource(QRegularExpression rx)
{
    return d_ptr->registerResource(rx);
}

void LSHttpd::unregisterResource(QSharedPointer<LSHttpdResource> resource)
{
    d_ptr->unregisterResource(resource);
}

LSHttpdRequest::LSHttpdRequest(QSslSocket *socket, QObject *parent) : QObject(parent), d_ptr(new LSHttpdRequestPrivate(this, socket))
{
}

LSHttpdRequest::~LSHttpdRequest()
{
    delete d_ptr;
}

void LSHttpdRequest::closeRequest()
{
    emit requestFinished();
}

QString LSHttpdRequest::resource() const
{
    return m_resource;
}

LSHttpd::ResponseCode LSHttpdRequest::responseCode() const
{
    return m_responseCode;
}

void LSHttpdRequest::setResponseCode(LSHttpd::ResponseCode value)
{
    m_responseCode = value;
}

QList<LSHttpdHeaderPair> LSHttpdRequest::requestHeaderList() const
{
    return m_requestHeaderList;
}

QList<LSHttpdHeaderPair> LSHttpdRequest::responseHeaderList() const
{
    return m_responseHeaderList;
}

void LSHttpdRequest::setResponseHeaderList(const QList<LSHttpdHeaderPair> &responseHeaderList)
{
    m_responseHeaderList = responseHeaderList;
}

QByteArray LSHttpdRequest::requestBodyData() const
{
    return m_requestBodyData;
}

QByteArray LSHttpdRequest::responseBodyData() const
{
    return m_responseBodyData;
}

void LSHttpdRequest::setResponseBodyData(const QByteArray &responseBodyData)
{
    m_responseBodyData = responseBodyData;
}

QByteArray LSHttpdRequest::requestRaw()
{
    return d_ptr->requestRaw();
}

bool LSHttpdRequest::validateResponse(QByteArray outData)
{
    return d_ptr->validateResponse(outData);
}

bool LSHttpdRequest::validateResponse()
{
    return d_ptr->validateResponse();
}

void LSHttpdRequest::response404()
{
    d_ptr->response404();
}
