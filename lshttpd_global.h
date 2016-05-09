#ifndef LSHTTPD_GLOBAL_H
#define LSHTTPD_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(LSHTTPD_LIBRARY)
#  define LSHTTPDSHARED_EXPORT Q_DECL_EXPORT
#else
#  define LSHTTPDSHARED_EXPORT Q_DECL_IMPORT
#endif

#endif // LSHTTPD_GLOBAL_H
