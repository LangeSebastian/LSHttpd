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

public:
    enum ResponseCode : int {
        OK = 200,                       //Ok Response Codes 2xx
        Created = 201,
        Accepted = 202,
        NoContent = 204,
        Redirection = 301,              //Redirect / Modification 3xx
        NotModified = 304,
        RedirectionTemporarely = 307,
        AuthRequired = 401,
        Forbidden = 403,
        NotFound = 404,                 //Request Error Responses 4xx
        MethodNotAllowed = 405,
        Gone = 410,
        ContentLengthRequired = 411,
        PreconditionFailed = 412,
        NotImplemented = 501            //Server Error Response 5xx
    };

private:
    QString m_resource;
    QString m_method;
    int m_responseCode;
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

    //Requested Url
    QString resource() const;
    QString method() const;

    //Status Code Response
    int responseCode() const;

    //Headers
    QList<LSHttpdHeaderPair> requestHeaderList() const;
    QList<LSHttpdHeaderPair> responseHeaderList() const;

    //Body
    QByteArray requestBodyData() const;
    QByteArray responseBodyData() const;

    QByteArray requestRaw();
    QByteArray responseRaw();

    void createResponse(int in_status, QList<LSHttpdHeaderPair> in_headerList, QByteArray in_bodyData);
    bool validateResponse(QByteArray outData);
    bool validateResponse();

    bool sendResponse();

    void response204();
    void response301(QByteArray redirectLocation);
    void response302(QByteArray redirectLocation);
    void response303(QByteArray redirectLocation);
    void response404();

    QByteArray extractOption(QByteArray headerValue, QByteArray optionTag);
    QByteArray extractUser(QByteArray headerValue);
    QByteArray extractDigest(QByteArray headerValue);
    QByteArray calculateDigestMD5(QString user, QString password, QByteArray realm, QByteArray nonce);

};

#endif // LSHTTPD_H
