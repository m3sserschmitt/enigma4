
#ifndef APP_H
#define APP_H

class Socket;

class App
{
public:
    virtual ~App(){};
    virtual int handleClient(Socket *) = 0;
};

#endif
