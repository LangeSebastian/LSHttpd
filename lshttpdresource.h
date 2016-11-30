#ifndef LSHTTPDRESOURCE_H
#define LSHTTPDRESOURCE_H

#include "lshttpd_global.h"

#include <QRegularExpression>
#include <QObject>

class LSHttpdRequest;

class LSHTTPDSHARED_EXPORT LSHttpdResource : public QObject
{
    Q_OBJECT
    friend class LSHttpdPrivate;

    explicit LSHttpdResource(QObject *parent = 0);

    bool m_valid;
    void invalidate();

    QRegularExpression m_resourceIdentifier;
    void setResourceIdentifier(const QRegularExpression &resourceIdentifier);

    void promoteRequest(LSHttpdRequest* request);
public:
    QRegularExpression resourceIdentifier() const;
    bool isValid() const;

signals:
    void pendingRequest(LSHttpdRequest* request);
    void resourceInvalidated();

public slots:

};

#endif // LSHTTPDRESOURCE_H
