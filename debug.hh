#ifndef DEBUG_HH
#define DEBUG_HH

#include <iostream>
#include "system_time.hh"

struct stream
{
    template <class T>
    friend stream &operator<<(stream &s, const T p)
    {
#ifndef DEBUG_OFF
        std::cout << p;
#endif
        return s;
    }
};

static stream debug_stream;

#define LOG(x) debug_stream << x;

#define PRINTLINE(x) debug_stream << x << "\n";
#define NPRINTLINE(x) debug_stream << "\n" \
                                   << x << "\n";

#define WARNING(x) debug_stream << "[-] Warning: " << get_system_time() << ": " << x << "\n";
#define FAILED(x) debug_stream << "[-] Failure: " << get_system_time() << ": " << x << "\n";

#define ERROR(x) debug_stream << "\n[-] Error:   " << get_system_time() << ": " << x << "\n";

#define NEWLINE() debug_stream << "\n";
#define INFO(x) debug_stream << "[+] Info:    " << get_system_time() << ": "<< x << "\n";

#endif
