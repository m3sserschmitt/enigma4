#include "onion_routing.hh"

#include <iostream>
#include <unistd.h>

OnionRoutingApp::OnionRoutingApp(){}

OnionRoutingApp::~OnionRoutingApp(){}

OnionRoutingApp &OnionRoutingApp::create_app()
{
    static OnionRoutingApp app = OnionRoutingApp();

    return app;
}

int OnionRoutingApp::handle_client(client_t c)
{
    write(c.sock, "hello", 5);

    return 0;
}
