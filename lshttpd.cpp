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

QList<LSHttpdHeaderPair> LSHttpdRequest::getRequestHeaderList() const
{
    return m_requestHeaderList;
}

QList<LSHttpdHeaderPair> LSHttpdRequest::getResponseHeaderList() const
{
    return m_responseHeaderList;
}

void LSHttpdRequest::setResponseHeaderList(const QList<LSHttpdHeaderPair> &responseHeaderList)
{
    m_responseHeaderList = responseHeaderList;
}

QByteArray LSHttpdRequest::getRequestBodyData() const
{
    return m_requestBodyData;
}

QByteArray LSHttpdRequest::getResponseBodyData() const
{
    return m_responseBodyData;
}

void LSHttpdRequest::setResponseBodyData(const QByteArray &responseBodyData)
{
    m_responseBodyData = responseBodyData;
}

bool LSHttpdRequest::validateResponse(QByteArray outData)
{
    return d_ptr->validateResponse(outData);
}

bool LSHttpdRequest::validateResponse()
{
    return d_ptr->validateResponse();
}
