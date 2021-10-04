# Enigma4
## Onion Routing App.

Enigma4 implements Onion Routing Protocol, which facilitate secure, end-to-end encrypted communications across the Internet. Before sending over the network, the client must apply several layers of encryption using the keys negotiated during the handshake. Then, before passing to the next one, every server that receives the message removes one layer of encryption using its own key.

## How it works

### Get source code

```
git clone https://github.com/m3sserschmitt/enigma4.git --recursive
```
### Compile source code

Open terminal into local repository then type

```
cmake -B./build
cd build
make all
```

There is a small example on how to create a basic client application into `example` directory.

### Setup a onion routing network

This is an example on how to setup a network consisting of only two servers.

Run the following commands into `build` directory:

Create a file `netfile1` with the following content:

`
localhost 8081 server2_public.pem
`

and a second file, `netfile2`:

`
localhost 8080 server1_public.pem
`

Run command:

```
./enigma4 -pubkey server1_public.pem -privkey server1_private.pem -netfile netfile1
```

and then, type into other terminal:

```
./enigma4 -pubkey server2_public.pem -privkey server2_private.pem -port 8081 -netfile2
```

This way, you will have two running servers, connected to each other.


