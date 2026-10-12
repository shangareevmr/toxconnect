# toxconnect

Tunnel TCP connections through the Tox peer-to-peer messaging protocol.

## Dependencies

- [toxcore](https://github.com/irungentoo/toxcore) (libtoxcore)
- [libsodium](https://github.com/jedisct1/libsodium)
- [libnice](https://gitlab.freedesktop.org/libnice/libnice) (for PseudoTCP)
- GLib/GIO (glib-2.0, gio-2.0, gobject-2.0)

## Build

```sh
gcc -Wall -Wextra $(pkg-config --cflags toxcore libsodium nice glib-2.0 gio-2.0 gobject-2.0) \
    main.c -o toxconnect \
    $(pkg-config --libs toxcore libsodium nice glib-2.0 gio-2.0 gobject-2.0)
```

## Usage

### Create a new Tox profile

```sh
./toxconnect -n -t myprofile.tox
```

### Add a friend

```sh
./toxconnect -f <tox_address_or_public_key> -t myprofile.tox
```

### Delete a friend

```sh
./toxconnect -d <tox_address_or_public_key> -t myprofile.tox
```

### Client mode (forward local TCP to remote service via Tox)

```sh
./toxconnect -c <local_port>:<friend_number>:<remote_port> -t client.tox
```

Example: listen on local port 8080, forward to friend #0's port 80:

```sh
./toxconnect -c 8080:0:80 -t client.tox
```

### Server mode (accept Tox tunnels and forward to local services)

```sh
./toxconnect -s -t server.tox
```

### Promiscuous mode (auto-accept friend requests)

```sh
./toxconnect -s -p -t server.tox
```

## How it works

- Each TCP connection is assigned a unique conversation ID: `(counter << 16) | remote_port`
- TCP data is sent over Tox lossy custom packets using libnice's `PseudoTCP` for reliability
- The server side demultiplexes incoming packets by conversation ID and connects to the appropriate local port
- The client side listens locally, creates a PseudoTCP connection per accepted socket, and tunnels data through Tox
