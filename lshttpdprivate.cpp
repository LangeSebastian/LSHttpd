#include "lshttpdprivate.h"
#include "lshttpd.h"

struct LSHttpd_Parser_Mapping {
    LSHttpdPrivate* obj;
    QSslSocket* socket;
};
static QMap<http_parser*,LSHttpd_Parser_Mapping> LSHTTPDPARSERMAP;

LSHttpdPrivate::LSHttpdPrivate(QHostAddress address, quint16 port, bool useSSL, LSHttpd *q) : QTcpServer(q), q_ptr(q)
{
    listen(address,port);
}

LSHttpdPrivate::~LSHttpdPrivate()
{
    qDeleteAll(m_sslSocketMap);
    m_sslSocketMap.clear();
}

int LSHttpdPrivate::onParserMessageCompleteWrapper(http_parser *parser)
{
    if(LSHTTPDPARSERMAP.contains(parser))
    {
        LSHttpd_Parser_Mapping m = LSHTTPDPARSERMAP.value(parser);
        return m.obj->onParserMessageComplete(m.socket,parser);
    }
    return -1;
}

int LSHttpdPrivate::onParserMessageComplete(QSslSocket *socket, http_parser *parser)
{
    //Verarbeiten der Anfrage
    socket->write("HTTP/1.1 404 Not Found\r\n\r\n\0");
    disconnectSocket(socket);
    return 0;
}

void LSHttpdPrivate::incomingConnection(qintptr handle)
{
    QSslSocket* s = new QSslSocket;
    if(s->setSocketDescriptor(handle))
    {
        LSHttpd_Connection_T *c = new LSHttpd_Connection_T;
        c->settings.on_message_complete = onParserMessageCompleteWrapper;
        http_parser_init(&c->parser,HTTP_REQUEST);

        LSHttpd_Parser_Mapping pm;
        pm.obj = this;
        pm.socket = s;

        m_sslSocketMap.insert(s,c);
        LSHTTPDPARSERMAP.insert(&c->parser,pm);

        connect(s,&QSslSocket::encrypted, this, [=](){
            connect(s,&QSslSocket::readyRead,this,&LSHttpdPrivate::readData);
        });
        connect(s,static_cast<void (QSslSocket::*)(const QList<QSslError> &)>(&QSslSocket::sslErrors),this,[=](){
            qDebug()<<"Socket SSLErrors:"<<s->sslErrors();
            s->ignoreSslErrors();
        });
        connect(s,static_cast<void (QSslSocket::*)(QAbstractSocket::SocketError)>(&QSslSocket::error),this,[=](){
            qDebug()<<"Socket Error:"<<s->error();
            disconnectSocket(s);
        });
        connect(s,&QSslSocket::disconnected,this,[=](){
            s->readAll();
            if(m_sslSocketMap.contains(s))
            {
                auto c = m_sslSocketMap.take(s);
                LSHTTPDPARSERMAP.remove(&c->parser);
                delete c;
            }
            delete s;
        });
    }else{
        delete s;
    }
}

void LSHttpdPrivate::disconnectSocket(QSslSocket *socket)
{
    socket->disconnect();
    socket->disconnectFromHost();
}

void LSHttpdPrivate::readData()
{
    QSslSocket* s = static_cast<QSslSocket*>(sender());
    if(!m_sslSocketMap.contains(s))
    {
        qDebug()<<"Socket Zombie found";
        disconnectSocket(s);
        return;
    }

    //Read Data into bytearray
    LSHttpd_Connection_T* c = m_sslSocketMap.value(s);
    c->data.append(s->readAll());

    //Parser for current data
    http_parser_execute(&c->parser,&c->settings,c->data.data(),c->data.size());
}
