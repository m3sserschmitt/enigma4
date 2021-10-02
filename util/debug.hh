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

template <class T>
void print_debug_message(T t)
{
    debug_stream << t << "\n";
}

template <typename T, class ... K>
void print_debug_message(T t, K ... k)
{
    debug_stream << t;
    print_debug_message(k...);
}

#define SUCCESS(...) print_debug_message(SUCCESS, __VA_ARGS__);
#define INFO(...) print_debug_message(INFO, __VA_ARGS__);
#define WARNING(...) print_debug_message(WARNING, __VA_ARGS__);
#define FAILURE(...) print_debug_message(FAILURE, __VA_ARGS__);
#define ERROR(...) print_debug_message(ERROR, __VA_ARGS__, "\n");

#define NEWLINE() print_debug_message("\n");

#endif
