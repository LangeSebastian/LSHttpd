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

    enum ParserState : int {
        STATE_NULL = 0,
        STATE_STATUS,
        STATE_URL,
        STATE_HEADERFIELD,
        STATE_HEADERVALUE,
        STATE_BODY
    };
    LSHttpdRequest *q_ptr;
    QScopedPointer<QSslSocket> m_socket;

    http_parser m_requestParser;
    http_parser_settings m_requestParserSettings;
    QByteArray m_requestData;
    bool m_requestComplete;
    ParserState m_requestParserState;

    http_parser m_responseParser;
    http_parser_settings m_responseParserSettings;
    QByteArray m_responseData;
    bool m_responseComplete;
    ParserState m_responseParserState;

    void onSocketReadyRead();

    qint64 m_responseBytesLeftToWrite;
    void bytesWritten(qint64 bytes);
    void writeData(QByteArray ba);

    void closeSocket();
    void closeRequest();

    friend class LSHttpdPrivate;

    QString parserMethodToString(int method);

public:
    LSHttpdRequestPrivate(LSHttpdRequest *ptr, QSslSocket* socket);
    ~LSHttpdRequestPrivate();

    http_parser* requestParser();
    http_parser_settings* requestParserSettings();

    http_parser* responseParser();
    http_parser_settings* responseParserSettings();

    void createResponse(int in_status, QList<LSHttpdHeaderPair> in_headerList, QByteArray in_bodyData);
    bool validateResponse(QByteArray outData);
    bool validateResponse();

    bool sendResponse();

    bool requestComplete() const;
    bool responseComplete() const;

    static int onNotificationNull(http_parser* p);
    static int onDataNull(http_parser* p, const char*at, size_t length);

    static int onMessageBeginCB(http_parser *parser);
    int onMessageBegin(http_parser *p);

    static int onUrlCB(http_parser* p, const char*at, size_t length);
    int onUrl(QByteArray in, http_parser* p);

    static int onStatusCB(http_parser* p, const char*at, size_t length);
    int onStatus(QByteArray in, http_parser* p);

    static int onHeaderFieldCB(http_parser* p, const char*at, size_t length);
    int onHeaderField(QByteArray in, http_parser* p);

    static int onHeaderValueCB(http_parser* p, const char*at, size_t length);
    int onHeaderValue(QByteArray in, http_parser* p);

    static int onHeaderCompleteCB(http_parser* p);
    int onHeaderComplete(http_parser *p);

    static int onBodyCB(http_parser* p, const char*at, size_t length);
    int onBody(QByteArray in, http_parser* p);

    static int onMessageCompleteWrapperCB(http_parser *parser);
    int onMessageComplete(http_parser* p);

    QByteArray requestRaw();
    QByteArray responseRaw();

    void response404();
    void response204();

signals:
    void requestCompleted(LSHttpdRequest* request);
    void responseCompleted(LSHttpdRequest* request);
};

#endif // LSHTTPDPRIVATE_H
