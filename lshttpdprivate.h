#ifndef LSHTTPDPRIVATE_H
#define LSHTTPDPRIVATE_H

#include <QTcpServer>
#include <QObject>
#include <QSslSocket>
#include <QList>
#include <QMap>

#include <http-parser/http_parser.h>

struct LSHttpd_Connection_T {
    http_parser parser;
    http_parser_settings settings;
    QByteArray data;
};


class LSHttpd;

class LSHttpdPrivate : public QTcpServer
{
public:
    LSHttpdPrivate(QHostAddress address, quint16 port, bool useSSL, LSHttpd *q);
    ~LSHttpdPrivate();

    static instance();

    static int onNotificationNull(http_parser* p);
    static int onDataNull(http_parser* p, const char*at, size_t length);
    static int onParserMessageCompleteWrapper(http_parser *parser);
    int onParserMessageComplete(QSslSocket *socket, http_parser *parser);

protected slots:
    void readData();

protected:
    LSHttpd *q_ptr;
    QMap<QSslSocket*, LSHttpd_Connection_T*> m_sslSocketMap;

    void incomingConnection(qintptr handle) Q_DECL_OVERRIDE;
    void disconnectSocket(QSslSocket* socket);

};

#endif // LSHTTPDPRIVATE_H
