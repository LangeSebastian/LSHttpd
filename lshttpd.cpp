#include "lshttpd.h"
#include "lshttpdprivate.h"
#include <QCryptographicHash>

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

QString LSHttpdRequest::method() const
{
    return m_method;
}

int LSHttpdRequest::responseCode() const
{
    return m_responseCode;
}

QList<LSHttpdHeaderPair> LSHttpdRequest::requestHeaderList() const
{
    return m_requestHeaderList;
}

QList<LSHttpdHeaderPair> LSHttpdRequest::responseHeaderList() const
{
    return m_responseHeaderList;
}

QByteArray LSHttpdRequest::requestBodyData() const
{
    return m_requestBodyData;
}

QByteArray LSHttpdRequest::responseBodyData() const
{
    return m_responseBodyData;
}

QByteArray LSHttpdRequest::requestRaw()
{
    return d_ptr->requestRaw();
}

QByteArray LSHttpdRequest::responseRaw()
{
    return d_ptr->responseRaw();
}

void LSHttpdRequest::createResponse(int in_status, QList<LSHttpdHeaderPair> in_headerList, QByteArray in_bodyData)
{
    d_ptr->createResponse(in_status,in_headerList,in_bodyData);
}

bool LSHttpdRequest::validateResponse(QByteArray outData)
{
    return d_ptr->validateResponse(outData);
}

bool LSHttpdRequest::validateResponse()
{
    return d_ptr->validateResponse();
}

bool LSHttpdRequest::sendResponse()
{
    return d_ptr->sendResponse();
}

void LSHttpdRequest::response204()
{
    d_ptr->response204();
}

void LSHttpdRequest::response301(QByteArray redirectLocation)
{
    d_ptr->response301(redirectLocation);
}

void LSHttpdRequest::response302(QByteArray redirectLocation)
{
    d_ptr->response302(redirectLocation);
}

void LSHttpdRequest::response303(QByteArray redirectLocation)
{
    d_ptr->response303(redirectLocation);
}

void LSHttpdRequest::response404()
{
    d_ptr->response404();
}

QByteArray LSHttpdRequest::extractOption(QByteArray headerValue, QByteArray optionTag)
{
    if(headerValue.isEmpty() || optionTag.isEmpty())
    {
        return QByteArray();
    }
    QString pattern = QStringLiteral("%1=\"([^\"]+)\"");
    QRegularExpression rx(pattern.arg(QString::fromLocal8Bit(optionTag)));
    auto rxMatch = rx.match(QString::fromLocal8Bit(headerValue));
    if(rxMatch.hasMatch())
    {
        return rxMatch.captured(1).toLocal8Bit();
    }
    return "";
}

QByteArray LSHttpdRequest::extractUser(QByteArray headerValue)
{
    return extractOption(headerValue,"username");
}

QByteArray LSHttpdRequest::extractDigest(QByteArray headerValue)
{
    return extractOption(headerValue,"response");
}

QByteArray LSHttpdRequest::calculateDigestMD5(QString user, QString password, QByteArray realm, QByteArray nonce)
{
    QByteArray ha1 = QCryptographicHash::hash(user.toLatin1()+':'+realm+':'+password.toLatin1(),QCryptographicHash::Md5).toHex();
    QByteArray ha2 = QCryptographicHash::hash(m_method.toLatin1()+':'+m_resource.toLatin1(),QCryptographicHash::Md5).toHex();
    QByteArray digest = QCryptographicHash::hash(ha1+':'+nonce+':'+ha2,QCryptographicHash::Md5).toHex();
    return digest;
}
