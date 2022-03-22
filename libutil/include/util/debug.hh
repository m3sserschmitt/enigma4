#ifndef DEBUG_HH
#define DEBUG_HH

#include <iostream>
#include <errno.h>
#include <string.h>

#include "system_time.hh"

#define DEBUG_ON

enum DebugMessageType
{
    SUCCESS = 0,
    INFO = 1,
    WARNING = 2,
    FAILURE = 3,
    ERROR = 4
};

struct stream
{
    friend stream &operator<<(stream &s, const DebugMessageType &mt)
    {
#ifdef DEBUG_ON
        switch (mt)
        {
        case SUCCESS:
            std::cout << "\x1B[32m[+] Success:\033[0m ";
            break;
        case INFO:
            std::cout << "\x1B[92m[+] Info:\033[0m    ";
            break;
        case WARNING:
            std::cout << "\x1B[33m[-] Warning:\033[0m ";
            break;
        case FAILURE:
            std::cout << "\x1B[91m[-] Failure:\033[0m ";
            break;
        case ERROR:
            std::cout << "\n\x1B[31m[-] Error:\033[0m   ";
            break;
        }

        std::cout << getSystemTime() << ": ";
#endif
        return s;
    }

    template <class T>
    friend stream &operator<<(stream &s, const T p)
    {
#ifdef DEBUG_ON
        std::cout << p;
#endif
        return s;
    }
};

static stream debugStream;

template <class T>
void printDebugMessage(T t)
{
#ifdef DEBUG_ON
    debugStream << t << "\n";
#endif
}

template <typename T, class ... K>
void printDebugMessage(T t, K ... k)
{
#ifdef DEBUG_ON
    debugStream << t;
    printDebugMessage(k...);
#endif
}

#define SUCCESS(...) printDebugMessage(SUCCESS, __VA_ARGS__);
#define INFO(...) printDebugMessage(INFO, __VA_ARGS__);
#define WARNING(...) printDebugMessage(WARNING, __VA_ARGS__);
#define FAILURE(...) printDebugMessage(FAILURE, __VA_ARGS__);
#define ERROR(...) printDebugMessage(ERROR, __VA_ARGS__, "\n");

#define NEWLINE() printDebugMessage("\n");


void printErrorDetails();

#endif
