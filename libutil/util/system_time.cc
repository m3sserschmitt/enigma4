#include "util/util.hh"
#include "util/system_time.hh"

#include <chrono>
#include <sstream>

// static const char *days[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
// static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Sep", "Oct", "Nov", "Dec"};

static char buffer[sizeof "9999-12-31 23:59:59.99999"];

const char *getSystemTime()
{
    // auto time_now = std::chrono::system_clock::now();
    // std::time_t current_time = std::chrono::system_clock::to_time_t(time_now);

    // return strip(std::ctime(&current_time), '\n');

    auto timepoint = std::chrono::system_clock::now();
    auto coarse = std::chrono::system_clock::to_time_t(timepoint);
    auto fine = std::chrono::time_point_cast<std::chrono::microseconds>(timepoint);

    // std::tm *now = localtime(&coarse);

    // std::stringstream ss;

    // ss << days[now->tm_mday] << " " << months[now->tm_mon] << " " << now->tm_mday;

    std::snprintf(buffer + std::strftime(buffer, sizeof buffer - 5,
                                         "%F %T.", std::localtime(&coarse)),
                  6, "%05lu", fine.time_since_epoch().count() % 100000);

    return buffer;
}