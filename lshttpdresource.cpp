#include "lshttpdresource.h"
#include <lshttpdprivate.h>

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
    if(receivers(SIGNAL(pendingRequest(LSHttpdRequest*))) > 0)
    {
        //TODO Timer for autoClose (HTTP 500) requests if socket idle for n secs.
        emit pendingRequest(request);
    }
    else
    {
        request->response500();
    }
}

QRegularExpression LSHttpdResource::resourceIdentifier() const
{
    return m_resourceIdentifier;
}
