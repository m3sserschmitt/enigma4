#include <iostream>
#include <unistd.h>

#include "client.hh"

#include <cryptography/cryptography.hh>

#include "cmd.hh"

using namespace std;

void gen_keys()
{
    CRYPTO::RSA_generate_keys("client_public2.pem", "client_private2.pem", 4096, 0, 0, 0, 0);
}

int main(int argc, char **argv)
{

    const char *ck = get_cmd_option(argv, argc, "-ck");

    if (not ck)
    {
        cout << "[-] Error: client public key is missing.\n";
        return EXIT_FAILURE;
    }

    const char *sk = get_cmd_option(argv, argc, "-sk");

    if (not sk)
    {
        cout << "[-] Error: server public key is missing.\n";
        return EXIT_FAILURE;
    }

    const char *pk = get_cmd_option(argv, argc, "-pk");

    if (not pk)
    {
        cout << "[-] Error: Client private key is missing\n";
        return EXIT_FAILURE;
    }

    const char *dk = get_cmd_option(argv, argc, "-dk");

    Client client(ck, pk);

    cout << "[+] Client address: " << client.get_client_hexaddress() << "\n";
    cout << "[+] Connection status: " << client.create_connection("localhost", "8080", sk) << "\n";

    string server_address = client.get_server_address();
    cout << "[+] Server address: " << server_address << "\n";

    string dest_address = client.add_node(dk, server_address);

    cout << "[+] Destination address: " << dest_address << "\n";

    string input;

    while (dest_address.size())
    {
        cout << "[+] Enter message: ";
        getline(cin, input);

        if(not input.size())
        {
            break;
        }

        client.write_data((BYTES)input.c_str(), input.size(), dest_address);
    }

    client.exit_circuit(dest_address);

    return 0;
}