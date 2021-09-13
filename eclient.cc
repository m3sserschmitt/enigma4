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

/*int main(int argc, char **argv)
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

    client.setup_server(sk);

    const BYTE *passphrase = (BYTES) "32bit-long passphrase for encryption";
    const BYTE *session_id = (BYTES) "this is id for session";

    string dest_address = client.setup_dest(dk, passphrase, session_id);

    cout << "[+] Destination address: " << dest_address << "\n";

    client.create_connection("localhost", "8080");
    client.handshake();

    string input;
    // if (dk)
    // {
    //     do
    //     {
    //         cout << "Would you like to exchange key with destination address? (y/n): ";
    //         cin >> input;

    //         if (input == "y")
    //         {
    //             client.send_dest_key(dest_address);
    //         }
    //     } while (input != "y" and input != "n");
    // }

    while (dest_address.size())
    {
        cout << "[+] Enter message: ";
        cin >> input;

        client.write_data((BYTES)input.c_str(), input.size(), dest_address);
    }

    return 0;
}*/