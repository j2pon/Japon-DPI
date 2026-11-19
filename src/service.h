#ifndef JAPONDPI_SERVICE_H
#define JAPONDPI_SERVICE_H

#include "dpi_engine.h"

#define JAPONDPI_SERVICE_NAME "JaponDPI"

/* Starts Windows Service control dispatcher and runs the DPI engine as a service */
int japondpi_run_as_service(DpiEngine *eng);

#endif /* JAPONDPI_SERVICE_H */
