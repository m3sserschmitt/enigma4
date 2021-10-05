# Enigma4
## Onion Routing App.

Enigma4 implements Onion Routing Protocol, which facilitate secure, private, end-to-end encrypted communications across the Internet. Before sending over the network, the client must apply several layers of encryption using the keys negotiated during the handshake. Then, before passing to the next one, every server that receives the message removes one layer of encryption using its own key.

## How it works

You need a GNU/Linux distribution in order to successfully get this project up and running.

### Get source code

```
git clone https://github.com/m3sserschmitt/enigma4.git --recursive
```
### Compile source code

Open terminal into local repository then type:

```
cmake -B./build
cd build
make all
```

There is a small example on how to create a basic client application into `example` directory.

### Setup a onion routing network

This is an example on how to setup a network consisting of only two servers.
Change current working directory to `tests`.

*.pem files are RSA keys used for asymmetric encryption (during handshake, session encryption keys must be protected while they are exchanged between client and server) and digital signatures (these are used to ensure message integrity and authenticity).

`netfile1` has the following content:

```
localhost 8081 server2_public.pem
```

and a second file, `netfile2`:

```
localhost 8080 server1_public.pem
```

This means that the first server will try to connect to the second one and vice-versa.

Run the following commands in two separate terminals:

```
./server1.sh
```

and then, type into other terminal:

```
./server2.sh
```

This way, you will have two running servers, connected to each other.

`circuit1` file contains the circuit used by `client1` in order to send messages to `client2`:

```
localhost 8080 server_public1.pem
server_public2.pem
client_public2.pem
```

These means that `client1` will connect to the `server1` which is listening for connections on `localhost`, port `8080`, and will use RSA public key `server_public1.pem` to communicate with `server1` before establishing a session key for symmetric encryption (AES CBC 256 in this case). After establishing a encryption key with `server1`, it will try to connect to `server2` using `server_public2.pem` and finally to `client2`; `netfile2` is similar.

Run

```
./client1.sh
```

and

```
./client2.sh
```

into two distinct terminals. If everything works fine you will be prompted to enter a message.

