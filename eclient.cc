#include <iostream>
#include <unistd.h>
#include <vector>

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

    const char *client_pubkey = get_cmd_option(argv, argc, "-pubkey");

    if (not client_pubkey)
    {
        cout << "[-] Error: client public key is missing.\n";
        return EXIT_FAILURE;
    }

    const char *client_privkey = get_cmd_option(argv, argc, "-privkey");

    if (not client_privkey)
    {
        cout << "[-] Error: Client private key is missing\n";
        return EXIT_FAILURE;
    }

    const char *circuit_file = get_cmd_option(argv, argc, "-circuit");

    if (not circuit_file)
    {
        cout << "[-] Error : circuit file is missing\n";
        return EXIT_FAILURE;
    }

    Client client(client_pubkey, client_privkey);
    cout << "[+] Client address: " << client.get_client_hexaddress() << "\n";

    string circuit_file_content = (const char *)read_file(circuit_file, "r");
    vector<string> entries = split(circuit_file_content, "\n", -1);
    vector<string> tokens = split(entries[0], " ", -1);

    if(tokens.size() != 3)
    {
        cout << "[-] Error: server connection failed.\n";
        return EXIT_FAILURE;
    }

    cout << "[+] Connection status: " << client.create_connection(tokens[0], tokens[1], tokens[2]) << "\n";

    string last_address = client.get_server_address();
    cout << "[+] Server address: " << last_address << "\n";

    for (size_t k = 1; k < entries.size(); k++)
    {
        if(not entries[k].size())
        {
            continue;
        }

        last_address = client.add_node(entries[k], last_address);
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

        client.write_data((BYTES)input.c_str(), input.size(), last_address);
    }

    client.exit_circuit(last_address);

    return 0;
}