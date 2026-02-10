## lite-xl-ssh

Non-blocking lua bindings of libssh2 for lite-xl or lua.

Allows you to open proejcts and files, as over an SSH connection, as if they were on your local drive.

Also, provides a library that can be included from `plugins.ssh.libssh`, that allows for non-blocking access to SSH tunnels.

To install:

```
lpm install https://github.com/adamharrison/lite-xl-ssh.git ssh
```

To configure:

```lua
config.plugins.ssh.auth = {
  {
     host = "localhost",
     user = "adam",
     password = "..."
  },
  {
     host = "raspberrypi",
     user = "adam",
     identity = "/home/adam/.ssh/raspberrypi"
  } 
}
```

Once configured, you can open a folder by simply calling `Core: Add Directory` on something like `ssh://adam@raspberrypi:/home/adam`.

You can also open individual files with a similar path.

### Building

#### Linux / Mac

```
./build.sh
```

#### Linux -> Windows

```
BIN=bin/libssh.x86_64-windows.dll CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-gcc-ar CMAKE_DEFAULT_FLAGS="-DCMAKE_SYSTEM_NAME=Windows" ./build.sh
```

I'm not sure if you can build on windows easily. I didn't try.


