#include "lshttpd.h"
#include "lshttpdprivate.h"
#include <QCryptographicHash>
#include <QMetaEnum>

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

LSHttpdRequest::LSHttpdRequest(QTcpSocket *socket, QObject *parent) : QObject(parent), d_ptr(new LSHttpdRequestPrivate(this, socket))
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

LSHttpdRequest::RequestMethod LSHttpdRequest::methodId() const
{
#if (QT_VERSION < QT_VERSION_CHECK(5,5,0))
    const QMetaObject *mo = this->metaObject();
    int index = mo->indexOfEnumerator("RequestMethod");
    QMetaEnum metaEnum = mo->enumerator(index);
#else
    QMetaEnum metaEnum = QMetaEnum::fromType<RequestMethod>();
#endif

    bool ok = false;
    int ret;
    ret = metaEnum.keyToValue(m_method.toLatin1().constData(),&ok);
    if(!ok)
    {
        ret = OTHER;
    }
    return static_cast<RequestMethod>(ret);
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

bool LSHttpdRequest::responseDefault(int responseCode)
{
    switch(responseCode)
    {
        case 200:
            response200();
            return true;
            break;
        case 204:
            response204();
            return true;
            break;
        case 400:
            response400();
            return true;
            break;
        case 403:
            response403();
            return true;
            break;
        case 404:
            response404();
            return true;
            break;
        case 410:
            response410();
            return true;
            break;
        case 411:
            response411();
            return true;
            break;
        case 412:
            response412();
            return true;
            break;
        case 500:
            response500();
            return true;
            break;
        case 501:
            response501();
            return true;
            break;
        case 502:
            response502();
            return true;
            break;
        case 503:
            response503();
            return true;
            break;
        case 504:
            response504();
            return true;
            break;
        default:
            return false;
            break;
    }
    return false;
}

void LSHttpdRequest::response200()
{
    d_ptr->response200();
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

void LSHttpdRequest::response304(QDateTime modificationDate)
{
    d_ptr->response304(modificationDate);
}

void LSHttpdRequest::response307(QByteArray redirectLocation)
{
    d_ptr->response307(redirectLocation);
}

void LSHttpdRequest::response400()
{
    d_ptr->response400();
}

void LSHttpdRequest::response401Basic(QByteArray realm)
{
    d_ptr->response401Basic(realm);
}

void LSHttpdRequest::response401Digest(QByteArray realm, QByteArray nonce)
{
    d_ptr->response401Digest(realm,nonce);
}

void LSHttpdRequest::response403()
{
    d_ptr->response403();
}

void LSHttpdRequest::response404()
{
    d_ptr->response404();
}

void LSHttpdRequest::response405(QStringList allowedMethods)
{
    d_ptr->response405(allowedMethods);
}

void LSHttpdRequest::response410()
{
    d_ptr->response410();
}

void LSHttpdRequest::response411()
{
    d_ptr->response411();
}

void LSHttpdRequest::response412()
{
    d_ptr->response412();
}

void LSHttpdRequest::response500()
{
    d_ptr->response500();
}

void LSHttpdRequest::response501()
{
    d_ptr->response501();
}

void LSHttpdRequest::response502()
{
    d_ptr->response502();
}

void LSHttpdRequest::response503()
{
    d_ptr->response503();
}

void LSHttpdRequest::response504()
{
    d_ptr->response504();
}

void LSHttpdRequest::responseOk()
{
    response200();
}

void LSHttpdRequest::responseNoContent()
{
    response204();
}

void LSHttpdRequest::responseMovedPermanently(QByteArray redirectLocation)
{
    response301(redirectLocation);
}

void LSHttpdRequest::responseFound(QByteArray redirectLocation)
{
    response302(redirectLocation);
}

void LSHttpdRequest::responseSeeOther(QByteArray redirectLocation)
{
    response303(redirectLocation);
}

void LSHttpdRequest::responseNotModified(QDateTime modificationDate)
{
    response304(modificationDate);
}

void LSHttpdRequest::responseTemporaryRedirect(QByteArray redirectLocation)
{
    response307(redirectLocation);
}

void LSHttpdRequest::responseBadRequest()
{
    response400();
}

void LSHttpdRequest::responseBasicAuth(QByteArray realm)
{
    response401Basic(realm);
}

void LSHttpdRequest::responseDigetsAuth(QByteArray realm, QByteArray nonce)
{
    response401Digest(realm,nonce);
}

void LSHttpdRequest::responseForbidden()
{
    response403();
}

void LSHttpdRequest::responseNotFound()
{
    response404();
}

void LSHttpdRequest::responseMethodNotAllowed(QStringList allowedMethods)
{
    response405(allowedMethods);
}

void LSHttpdRequest::responseGone()
{
    response410();
}

void LSHttpdRequest::responseLengthRequired()
{
    response411();
}

void LSHttpdRequest::responsePreconditionFailed()
{
    response412();
}

void LSHttpdRequest::responseServerError()
{
    response500();
}

void LSHttpdRequest::responseNotImplemented()
{
    response501();
}

void LSHttpdRequest::responseBadGateway()
{
    response502();
}

void LSHttpdRequest::responseServiceUnavailable()
{
    response503();
}

void LSHttpdRequest::responseGateWayTimeout()
{
    response504();
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
