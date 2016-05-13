#include "lshttpdresource.h"

LSHttpdResource::LSHttpdResource(QObject *parent) : QObject(parent)
{
    m_valid = true;
}

void LSHttpdResource::invalidate()
{
    m_valid = false;
    emit resourceInvalidated();
}

bool LSHttpdResource::isValid() const
{
    return m_valid;
}

void LSHttpdResource::setResourceIdentifier(const QRegularExpression &resourceIdentifier)
{
    m_resourceIdentifier = resourceIdentifier;
}

void LSHttpdResource::promoteRequest(LSHttpdRequest *request)
{
    emit pendingRequest(request);
}

QRegularExpression LSHttpdResource::resourceIdentifier() const
{
    return m_resourceIdentifier;
}
