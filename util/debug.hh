#ifndef DEBUG_HH
#define DEBUG_HH

#include <iostream>
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

        std::cout << get_system_time() << ": ";
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

static stream debug_stream;

// #define LOG(x) debug_stream << x;

// #define PRINTLINE(x) debug_stream << x << "\n";
// #define NPRINTLINE(x) debug_stream << "\n" \
//                                    << x << "\n";

#define SUCCESS(x) debug_stream << SUCCESS << x << "\n";
#define INFO(x) debug_stream << INFO << x << "\n";
#define WARNING(x) debug_stream << WARNING << x << "\n";
#define FAILURE(x) debug_stream << FAILURE << x << "\n";
#define ERROR(x) debug_stream << ERROR << x << "\n\n";

#define NEWLINE() debug_stream << "\n";

#endif
