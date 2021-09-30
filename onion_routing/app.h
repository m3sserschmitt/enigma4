
#ifndef APP_H
#define APP_H


class App
{
public:
    virtual ~App(){};
    virtual int handle_client(int) = 0;
};

#endif
