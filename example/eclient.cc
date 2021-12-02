#include <iostream>
#include <unistd.h>
#include <vector>

#include "../onion_routing/client.hh"

#include "../libcryptography/include/cryptography.hh"

#include "../util/cmd.hh"

using namespace std;

void gen_keys()
{
    CRYPTO::RSA_generate_keys("client_public2.pem", "client_private2.pem", 4096, 0, 0, 0, 0);
}

int printMessageContent(MessageParser &mp)
{
    cout << "New message received:" << mp.getPayload() << "\n";

    return 0;
}

int main(int argc, char **argv)
{

    const char *client_pubkey = getCmdOption(argv, argc, "-pubkey");

    if (not client_pubkey)
    {
        cout << "[-] Error: client public key is missing.\n";
        return EXIT_FAILURE;
    }

    const char *client_privkey = getCmdOption(argv, argc, "-privkey");

    if (not client_privkey)
    {
        cout << "[-] Error: Client private key is missing\n";
        return EXIT_FAILURE;
    }

    const char *circuit_file = getCmdOption(argv, argc, "-circuit");

    if (not circuit_file)
    {
        cout << "[-] Error : circuit file is missing\n";
        return EXIT_FAILURE;
    }

    Client client(client_pubkey, client_privkey);
    client.onIncomingMessage(printMessageContent);

    cout << "[+] Client address: " << client.getClientHexaddress() << "\n";

    string circuit_file_content = (const char *)readFile(circuit_file, "r");
    vector<string> entries = split(circuit_file_content, "\n", -1);
    vector<string> tokens = split(entries[0], " ", -1);

    if (tokens.size() != 3)
    {
        cout << "[-] Error: server connection failed.\n";
        return EXIT_FAILURE;
    }

    cout << "[+] Connection status: " << client.createConnection(tokens[0], tokens[1], tokens[2]) << "\n";

    string last_address = client.getServerAddress();
    cout << "[+] Server address: " << last_address << "\n";

    SIZE circuit_length = entries.size();

    for (size_t k = 1; k < circuit_length; k++)
    {
        if (not entries[k].size())
        {
            continue;
        }

        if (k == circuit_length - 1)
        {
            last_address = client.addNode(entries[k], last_address, 1);
        }
        else
        {
            last_address = client.addNode(entries[k], last_address);
        }
    }

    string input;

    while (1)
    {
        cout << "[+] Enter message: ";
        getline(cin, input);

        if (not input.size())
        {
            break;
        }

        client.writeDataWithEncryption((BYTES)input.c_str(), input.size(), last_address);
    }

    client.sendExitSignal(last_address);

    return 0;
}