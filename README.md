```
         __       __   ______        ___      ___       ____  ____    ____  ______
        |  |     |  | |   _  \      /   \    |    \    /    | \   \  /   / |   _  \
        |  |     |  | |  |_)  |    /  .  \   |  .  \  /  .  |  \   \/   /  |  |_)  |
        |  |     |  | |   _  <    /  /_\  \  |  |\  \/  /|  |   \      /   |   ___/
        |  `----.|  | |  |_)  |  /  _____  \ |  | \    / |  |    \    /    |  |
        |_______||__| |______/  /__/     \__\|__|  '--'  |__|     \__/     |__|   

            A library that implements the client-side of the AMVP protocol.
```

## License
Libamvp is licensed under the Apache License 2.0, which means that
you are free to get and use it for commercial and non-commercial
purposes as long as you fulfill its conditions. See the LICENSE
file for details.


## Recent Changes

This document will be updated as more details are worked out and finalized on the AMVP project.


# Overview

Libamvp is a client-side AMVP library implementation, and also includes
an example application (amvp_app) which utilizes the library.

We request that users limit issue reports and discussion at this time as many protocol and
implementation details are still in active and early development.

## Dependencies
* autotools
* gcc
* make
* curl (or substitution)
* openssl (or substitution)

Curl is used for sending REST calls to the AMVP server.

Openssl is used for TLS transport by libcurl.

Parson is used to parse and generate JSON data for the REST calls.
The parson code is included and compiled as part of libamvp.

libcurl, libssl and libcrypto are not included, and must
be installed separately on your build/target host,
including the header files.


## Building

`--prefix<path to install dir>` can be used with any configure options to specify where you would
like the library and application to install to. 

`configure` searches for an OpenSSL install and a libcurl install. They can be provided manually if not found.
The build system will be updated with fixes soon, and this document will be updated with more details.

## Running

This section will be updated with details as more protocol details are finalized.
