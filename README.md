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
This document is currently a copy from libacvp and will be modified as development ramps up on AMVP.


# Overview

Libamvp is a client-side AMVP library implementation, and also includes
an example application (amvp_app) which utilizes the library.

The `app/` directory contains a sample application which uses libamvp.

The `certs/` directory contains the certificates used to establish a TLS
session with well-known AMVP servers. If the AMVP server uses a self-signed certificate,
then the proper CA file must be specified.
libamvp also requires a client certificate and key pair,
which the AMVP server uses to identify the client. You will need to
contact NIST to register your client certificate with their server.


## Dependencies
* autotools
* gcc
* make
* curl (or substitution)
* openssl (or substitution)
* libcriterion (for unit tests only)
* doxygen (for building documentation only)

Curl is used for sending REST calls to the AMVP server.

Openssl is used for TLS transport by libcurl.

Parson is used to parse and generate JSON data for the REST calls.
The parson code is included and compiled as part of libamvp.

libcurl, libssl and libcrypto are not included, and must
be installed separately on your build/target host,
including the header files.

##### Dealing with system-default dependencies
This codebase uses features in OpenSSL >= 1.1.1.
If the system-default install does not meet this requirement,
you will need to download, compile and install at least OpenSSL 1.1.1 on your system.
The new OpenSSL resources should typically be installed into /usr/local/ssl to avoid
overwriting the default OpenSSL that comes with your distro.

Version 1.1.1 of OpenSSL reaches end of life officially on September 11, 2023. Updating to OpenSSL
3.X is highly recommended when possible. All previous versions have reached end of life status.

A potential source of issues is the default libcurl on the Linux distro, which may be linked against
the previously mentioned default OpenSSL. This could result in linker failures when trying to use
the system default libcurl with the new OpenSSL install (due to missing symbols).
Therefore, you SHOULD download the Curl source, compile it against the "new" OpenSSL
header files, and link libcurl against the "new" OpenSSL. 
libamvp uses compile time macro logic to address differences in the APIs of different OpenSSL
versions; therefore, it is important that you ensure libamvp is linking to the correct openSSL versions
at run time as well.

Libamvp is designed to work with curl version 7.80.0 or newer. Some operating systems may ship with
older versions of Curl which are missing certain features that libamvp depends on. In this case you
should either acquire a newer version through your OS package manager if possible or build a newer
version from source. While it is possible some older versions may work, they are not tested or
supported.

## Building

`--prefix<path to install dir>` can be used with any configure options to specify where you would
like the library and application to install to. 

#### To build app and library for supported algorithm testing

```
./configure --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>
make clean
make
make install
```

#### Building libamvp without the application code.
Use the following ./configure comand line option and only the library will be built and installed.

--disable-app

Note that this option is not useful when building for offline testing since the application is needed.
Using this option, only a libcurl installation dir needs to be provided.
 
#### Building amvp_app only without the library code
Use the following ./configure comand line option and only the app will be built. Note that it depends
on libamvp having already been built. The libamvp directory can be provided using --with-libamvp-dir=
Otherwise, it will look in the default build directory in the root folder for libamvp.

--disable-lib

#### Other build options
More info about all available configure options can be found by using ./configure --help. Some important
ones include:
--enable-offline : Will link to all dependencies statically and remove the libcurl dependency. See "How
 to test offline" for more details. NOTE: Support for statically linking OpenSSL 3.X is not supported
 at this time. OpenSSL does not support static linking of the FIPS provider. Support for statically
 linking other dependencies will be added.
--disable-kdf : Will disable kdf registration and processing in the application, in cases where the given
 crypto implementation does not support it (E.g. all OpenSSL prior to 3.0)
--disable-lib-check : This will disable autoconf's attempts to automatically detect prerequisite libraries
 before building libamvp. This may be useful in some edge cases where the libraries exist but autoconf
 cannot detect them; however, it will give more cryptic error messages in the make stage if there are issues


#### Cross Compiling
Requires options --build and --host.
Your `$PATH` must contain a path the gcc.

```
export CROSS_COMPILE=powerpc-buildroot-linux-uclibc
./configure --build=<local target prefix> --host=<gcc prefix of target host> --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>
```

Example with build and host information:
```
./configure --build=localx86_64-unknown-linux-gnu --host=mips64-octeon-linux-gnu --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>`
```
All dependent libraries must have been built with the same cross compile.

If using murl for cross compliles use the same CROSS_COMPILE and HOSTCC used with openssl, for example:

CROSS_COMPILE=arm-linux-gnueabihf-
HOSTCC=gcc

## Windows
The Visual Studio projects for amvp_app and libamvp are set to use 2017 tools and are designed to
be easily updated to use the latest versions of Microsoft build tools while being backwards
compatible with Visual Studio 2017 and some older Windows 10 SDK versions.

Prerequisites:
This system assumes all dependency library paths have /include folders containing all the headers
needed to properly link. This can be altered in the scripts if needed.

For amvp_app, If you are using a FIPS Object Module with OpenSSL: you need a header in your 
/include folder that maps FIPS functions to SSL ones (for example, fipssyms.h) which is sometimes
not moved to the install path from the source path by default on Windows.

For these steps, use the Visual Studio Command Prompt for your platform (x64, x86, x86_64, or 
x64_86)

Steps:
1.) Edit and run ms\config_windows.bat
    -Add all of the directories for your dependencies
	-Change any needed settings
2.) Open libamvp.sln and amvp_app.sln in Visual Studio and allow the dialog to update the projects'
    versions of MSVC and windows SDK to the latest installed (May be unnecessary if versions match)
3.) run ms/make_lib.bat
4.) run ms/make_app.bat

The library files and app files will be placed in the ms/build/ directory.

Notes:
Windows will only search specific paths for shared libraries, and will not check the
locations you specify in config_windows.bat by default unless they are in your path. This results
in amvp_app not being able to run. An alternative to altering your path or moving libraries to
system folders is moving/copying any needed .dll files to the same directory as amvp_app.

If you are building statically, it is assumed for amvp_app that you have built Curl with OpenSSL, 
and that you are linking amvp_app to the exact same version of OpenSSL that Curl is linked to. Other
configurations are not supported, untested, and may not work. Libamvp itself is indifferent
to which crypto and SSL libraries Curl uses, but any applications using libamvp statically
need to link to those libraries.

Murl is not supported in windows at this time.

## Running
1. `export LD_LIBRARY_PATH="<path to ssl lib;path to curl lib>"`
2. Modify scripts/nist_setup.sh and run `source scripts/nist_setup.sh`
3. `./app/amvp_app --<options>`

Use `./app/amvp_app --help` for more information on available options.

libamvp generates a file containing information that can be used to resume or check the results
of a session. By default, this is usually placed in the folder of the executable utilizing
libamvp, though this can be different on some OS. The name, by default, is
testSession_(ID number).json. The path and prefix can be controlled using ACV_SESSION_SAVE_PATH
and ACV_SESSION_SAVE_PREFIX in your environment, respectively. 

### How to test offline
1. Download vectors on network accessible device:
`./app/amvp_app --<algs of choice or all_algs> --vector_req <filename1>`
 - where `<filename1>` is the file you are saving the tests to.

2. Copy vectors and amvp_app to target:
`./app/amvp_app --all_algs --vector_req <filename1> --vector_rsp <filename2>`
 - where `<filename1>` is the file the tests are saved in, and `<filename2>` is the file
you want to save your results to.

3. Copy responses(filename2) to network accessible device:
`./app/amvp_app --all_algs --vector_upload <filename2>`
 - where `<filename2>` is the file containing the results of the tests.

*Note:* The below does not yet apply to OpenSSL 3.X
*Note:* If the target in Step 2 does not have the standard libraries used by
libamvp you may configure and build a special app used only for Step 2. This
can be done by using --enable-offline and --enable-static when running 
./configure and do not use --with-libcurl-dir or --with-libmurl-dir which
will  minimize the library dependencies. Note that openssl with FOM must also
be built as static. For this case, OpenSSL MUST be built with the "no-dso" option,
OR the configure option `--enable-offline-ldl-check` must be used to resolve the libdl
dependency. Some specific versions of SSL may not be able to remove the libdl dependency.

## Testing
Move to the test/ directory and see the README.md there. The tests depend upon
a C test framework called Criterion, found here: https://github.com/Snaipe/Criterion


## Contributing
Before opening a pull request on libamvp, please ensure that all unit tests are
passing. Additionally, new tests should be added for new library features.

Any and all new API functions must also be added to ms\resources\source.def.
