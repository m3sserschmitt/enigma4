#include "network_bridge.hh"

using namespace std;

string NetworkBridge::pubkeyfile;
string NetworkBridge::privkeyfile;

map<string, Client *> NetworkBridge::remoteServers;

IncomingMessageCallback NetworkBridge::incomingMessageCallback = 0;