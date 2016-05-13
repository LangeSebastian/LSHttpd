#ifndef LSHTTPD_H
#define LSHTTPD_H

#include "lshttpd_global.h"

#include <QObject>
#include <QTcpServer>
#include <QHostAddress>
#include <QTcpSocket>
#include <QSsl>
#include <QSslKey>
#include <QSslCertificate>
#include <QByteArray>
#include <QPair>
#include <QSslSocket>
#include <QRegularExpression>

class LSHttpdPrivate;
class LSHttpdRequestPrivate;
class LSHttpdResource;

typedef QPair<QString,QString> LSHttpdHeaderPair;

class LSHTTPDSHARED_EXPORT LSHttpd : public QObject
{
    Q_OBJECT

public:
    enum ResponseCode : int {
        OK = 200,                       //Ok Response Codes 2xx
        Created = 201,
        Accepted = 202,
        NoContent = 204,
        Redirection = 301,              //Redirect / Modification 3xx
        NotModified = 304,
        NotFound = 404,                 //Request Error Responses 4xx
        MethodNotAllowed = 405,
        Gone = 410,
        PreconditionFailed = 412,
        NotImplemented = 501            //Server Error Response 5xx
    };

    LSHttpd(QHostAddress address=QHostAddress::Any, quint16 port=80, bool useSSL=false);
    void setCertificate(const QString &path, QSsl::EncodingFormat format = QSsl::Pem);
    void setCertificate(const QSslCertificate & certificate);
    void setPrivateKey(const QString &path, QSsl::KeyAlgorithm keyAlgorithm = QSsl::Rsa, QSsl::EncodingFormat format = QSsl::Pem, const QByteArray & passPhrase = QByteArray());
    void setPrivateKey(const QSslKey &key);

    QSharedPointer<LSHttpdResource> registerFallback();    //Custom handling of 404 etc.
    void unregisterFallback();
    QSharedPointer<LSHttpdResource> registerResource(QRegularExpression rx);   //rx match for relative Url
    void unregisterResource(QSharedPointer<LSHttpdResource> resource);

signals:

protected:
    LSHttpd(LSHttpdPrivate &d);
    LSHttpdPrivate *d_ptr;

};

class LSHTTPDSHARED_EXPORT LSHttpdRequest : public QObject
{
    Q_OBJECT

    QString m_resource;
    LSHttpd::ResponseCode m_responseCode;
    QList<LSHttpdHeaderPair> m_requestHeaderList;
    QList<LSHttpdHeaderPair> m_responseHeaderList;
    QByteArray m_requestBodyData;
    QByteArray m_responseBodyData;

    LSHttpdRequestPrivate *d_ptr;

    friend class LSHttpdPrivate;
    friend class LSHttpdRequestPrivate;

    LSHttpdRequest(QSslSocket* socket, QObject *parent=0);

    void closeRequest();

signals:
    void requestFinished();

public:
    ~LSHttpdRequest();

    QString resource() const;
    LSHttpd::ResponseCode responseCode() const;
    void setResponseCode(LSHttpd::ResponseCode value);
    QList<LSHttpdHeaderPair> requestHeaderList() const;
    QList<LSHttpdHeaderPair> responseHeaderList() const;
    void setResponseHeaderList(const QList<LSHttpdHeaderPair> &responseHeaderList);
    QByteArray requestBodyData() const;
    QByteArray responseBodyData() const;
    void setResponseBodyData(const QByteArray &responseBodyData);
    QByteArray requestRaw();

    bool validateResponse(QByteArray outData);
    bool validateResponse();

    void response404();

};

#endif // LSHTTPD_H
