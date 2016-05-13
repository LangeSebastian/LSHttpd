#ifndef LSHTTPDPRIVATE_H
#define LSHTTPDPRIVATE_H

#include <QTcpServer>
#include <QObject>
#include <QSslSocket>
#include <QList>
#include <QMap>

#include <lshttpd.h>
#include <http-parser/http_parser.h>

class LSHttpdPrivate : public QTcpServer
{
    Q_OBJECT
public:
    LSHttpdPrivate(QHostAddress address, quint16 port, bool useSSL, LSHttpd *q);
    ~LSHttpdPrivate();

    void setCertificate(const QString &path, QSsl::EncodingFormat format);
    void setCertificate(const QSslCertificate & certificate);
    void setPrivateKey(const QString &path, QSsl::KeyAlgorithm keyAlgorithm, QSsl::EncodingFormat format, const QByteArray & passPhrase = QByteArray());
    void setPrivateKey(const QSslKey &key);

    QSharedPointer<LSHttpdResource> registerFallback();
    void unregisterFallback();
    QSharedPointer<LSHttpdResource> registerResource(QRegularExpression rx);
    void unregisterResource(QSharedPointer<LSHttpdResource> resource);

protected:
    LSHttpd *q_ptr;

    QVector<LSHttpdRequest*> m_openRequests;

    QSharedPointer<LSHttpdResource> m_fallBackResource;
    QVector< QSharedPointer<LSHttpdResource> > m_registeredResources;

    QSslCertificate m_sslCert;
    QSslKey m_sslKey;

    void incomingConnection(qintptr handle) Q_DECL_OVERRIDE;
    void removeRequest();
    void mapRequestToResource(LSHttpdRequest *request);

};

class LSHttpdRequestPrivate : public QObject
{
    Q_OBJECT

    LSHttpdRequest *q_ptr;
    QScopedPointer<QSslSocket> m_socket;

    http_parser m_requestParser;
    http_parser_settings m_requestParserSettings;
    QByteArray m_requestData;
    bool m_requestComplete;

    http_parser m_responseParser;
    http_parser_settings m_responseParserSettings;
    QByteArray m_responseData;
    bool m_responseComplete;

    void onSocketReadyRead();

    void closeSocket();
    void closeRequest();

    friend class LSHttpdPrivate;

public:
    LSHttpdRequestPrivate(LSHttpdRequest *ptr, QSslSocket* socket);
    ~LSHttpdRequestPrivate();

    http_parser* requestParser();
    http_parser_settings* requestParserSettings();

    http_parser* responseParser();
    http_parser_settings* responseParserSettings();

    bool validateResponse(QByteArray outData);
    bool validateResponse();

    bool requestComplete() const;
    bool responseComplete() const;

    static int onNotificationNull(http_parser* p);
    static int onDataNull(http_parser* p, const char*at, size_t length);

    static int onRequestMessageCompleteWrapper(http_parser *parser);
    int onRequestMessageComplete();

    QByteArray requestRaw();

    void response404();

signals:
    void requestCompleted(LSHttpdRequest* request);

};

#endif // LSHTTPDPRIVATE_H
