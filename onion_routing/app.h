
#ifndef APP_H
#define APP_H


class App
{
public:
    virtual ~App(){};
    virtual int handleClient(int) = 0;
};

#endif
