# Libamvp Client Development using Docker

This document will go over how use Docker to build Libamvp along with it's example application (amvp\_app). Currently, OpenSSL is used as the cryptographic module provider.
Please keep in mind that this tool is intended to help the developer, and it is NOT required to be maintained as part of the codebase. In other words, if you choose to use these tools, you are on your own.

## Building the Docker Image

Inside the libamvp/docker directory, you will find subdirectories that each contain a Dockerfile.
Each subdirectory's Dockerfile will correspond to a seperate set of dependencies... mostly they will differ according to which crypto module that Libamvp/amvp\_app will test.
The environment with required dependencies will be setup according to the Dockerfile which is built by the developer. For instance, if the developer builds openssl\_102/Dockerfile, then a recent OpenSSL 1.0.2 release will be used as the crypto module to be tested.
You can read the README under each subdir to get a better description of what that specific environment will contain.
A Docker image can be built using this file, and then the developer will mount the libamvp/ directory as a volume.
Mounting the libamvp/ directory will ensure that any code changes made within the container do not disappear when the container is terminated.
The resulting Docker container will have Vim and Emacs installed by default… of course the developer can add packages to the container as needed within the Dockerfile!

#### Getting Libamvp
```
git clone https://github.com/cisco/libamvp.git
cd libamvp/
```

#### Libamvp with OpenSSL 1.0.2
```
cd docker/openssl_102
docker build -t libamvp_w_openssl102 .
```

#### Libamvp with OpenSSL 1.1.0
```
cd docker/openssl_110
docker build -t libamvp_w_openssl110 .
```

#### Libamvp with OpenSSL 1.1.1
```
cd docker/openssl_111
docker build -t libamvp_w_openssl111 .
```

**Note:** The sudo password inside the running container is “docker”.

## Running the Docker Container

In this section, you will run the appropriate container using the image that was built previously.
The `-v` option is used to mount the libamvp/ directory from the host machine, so that changes are persistently stored.
The `--user` option is so that any file touched within the container are owned by the host machine's User.

Start at the root libamvp/ directory...

#### Libamvp with OpenSSL 1.0.2
```
docker run -v $(pwd):/home/docker/libamvp --user $(id -u) -it libamvp_w_openssl102
```

#### Libamvp with OpenSSL 1.1.0
```
docker run -v $(pwd):/home/docker/libamvp --user $(id -u) -it libamvp_w_openssl110
```

#### Libamvp with OpenSSL 1.1.1
```
docker run -v $(pwd):/home/docker/libamvp --user $(id -u) -it libamvp_w_openssl111
```

## Building Libamvp
Now that you are inside the running container with all required/installed dependencies, you will need to build Libamvp and the example application.
Libamvp will be linked against the $CURL\_INSTALL which is needed for data transport operations.
The example application will be linked against the crypto module located at $OPENSSL\_INSTALL.

```
./configure --with-ssl-dir=$OPENSSL_INSTALL --with-libcurl-dir=$CURL_INSTALL
make
```

Here's an example of how to build with debug symbols:

```
CFLAGS="-O0 -g" ./configure --with-ssl-dir=$OPENSSL_INSTALL --with-libcurl-dir=$CURL_INSTALL
make
```

## Environment Variables

There are a few environment variables that need to be set for the amvp\_app application to work.

```
export ACV_SERVER="demo.amvts.nist.gov"
export ACV_PORT="443"
export ACV_URI_PREFIX="amvp/v1/"
export ACV_API_CONTEXT="amvp/"
```

These following variables will be determined by the authentication and connection TLS requirements imposed by the server:

```
export ACV_CERT_FILE="<PATH_TO_CLIENT_CERT>"
export ACV_KEY_FILE="<PATH_TO_CLIENT_PRIVATE_KEY>"
export ACV_CA_FILE="<PATH_TO_CA_FILE_FOR_SERVER_VERIFICATION>"
export ACV_TOTP_SEED="<PROVIDED_BY_NIST>"
```

## Run the application

Now to simply kick off the application, execute the binary!

`./app/amvp_app --help`

