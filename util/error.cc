#include "debug.hh"

void printErrorDetails()
{
    ERROR("The following error occurred: ", strerror(errno));
}