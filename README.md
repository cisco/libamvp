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

This project is intended to be a reference implementation for the AMVP protocol. It is heavily
under construction and based upon the work done for libacvp. We will happily accept issue reports
and code contributions at this time. We also encourage developers to use this project
as a basis for ports to languages of their preference.

This client is not intended to collect or process any data related to the AMVP process itself.
It is intended only to facilitate the transfer of the data through the AMVP protocol and display
user-relevant data in an easier to read way.

## Contributing

There is much work to do and we are happy to accept the following contributions at this time:

* Code readability improvements
* Code functionality improvements
* User experience improvements
* Removal of dead code
* Removal of hard coded values/reorganization of hard defined strings/variables
* Autoconf build fixes/improvements
* Windows build uplift (not tested/maintained to date)
* Addition of logo upload functionality to security policy generation
* Unit test fixes/removals/additions (not tested/maintained to date)
* Improved handling of TOTP seed (support for multiple TOTP seeds; caching which seeds have been
  recently used)
* etc

We welcome any of the above changes to be included in a pull request, into the main branch. We
reserve the right to reject changes for any reason. We will also consider substantial changes to
usage flow if they are well justified.

We will also consider well-documented PRs for feature additions. Please consider the scope of this
project as a reference implementation; we will happily accept general features to help users
interact with the server as they develop their own AMVP clients, but specialized, niche, or very
complex features will not be considered. Thank you for your understanding.


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

`--prefix=<path to install dir>` can be used with any configure options to specify where you would
like the library and application to install to. 

`configure` searches for an OpenSSL install and a libcurl install. They can be provided manually if not found.
The build system will be updated with fixes soon, and this document will be updated with more details.

## Running

This section will be updated with details as soon as possible.
