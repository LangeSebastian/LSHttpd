#ifndef LSHTTPDRESOURCE_H
#define LSHTTPDRESOURCE_H

#include <QObject>

class LSHttpdRequest;

class LSHttpdResource : public QObject
{
    Q_OBJECT

    QList<LSHttpdRequest*> m_openRequests;

    explicit LSHttpdResource(QObject *parent = 0);

    friend class LSHttpdPrivate;
public:

signals:
    void requestStarted(); //
public slots:

};

#endif // LSHTTPDRESOURCE_H
