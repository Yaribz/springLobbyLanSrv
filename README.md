springLobbyLanSrv
=================

A Spring lobby server running in LAN mode, fast and easy to use

Usage
=====

    springLobbyLanSrv [options]
    
      Options:
        -a,--address <addr>  : specify listening address (default: all)
        -c,--country <CC>    : specify country code assigned to clients
        -d,--debug           : show debug messages (very verbose)
        -h,--help            : print usage
        -p,--port <n>        : specify listening port (default: 8200)
        -q,--quiet           : remove output
        -r,--redirect <addr> : enable redirect mode
        -v,--version         : print version
        -w,--wan <addr>      : force manual WAN address for LAN-to-WAN hosting
        -W,--no-wan          : disable support for LAN-to-WAN hosting through NAT

Downloads (binaries)
====================

No dependency, no installation needed (self-signed certificates are auto-generated in script directory)

* [springLobbyLanSrv.exe](https://github.com/Yaribz/springLobbyLanSrv/releases/latest/download/springLobbyLanSrv.exe) (Windows)
* [springLobbyLanSrv](https://github.com/Yaribz/springLobbyLanSrv/releases/latest/download/springLobbyLanSrv) (Linux)

Perl script
===========

For systems incompatible with the provided binaries, the packaged Perl script [springLobbyLanSrv.pl](https://github.com/Yaribz/springLobbyLanSrv/releases/latest/download/springLobbyLanSrv.pl) is also available but it requires installing a few dependencies as described hereafter.

Prerequisites for Windows
-------------------------

* Install [Strawberry Perl](https://strawberryperl.com/)

* Install the `AnyEvent` Perl module using command `cpanm -n AnyEvent`

Prerequisites for Linux
-----------------------

The `IO::Socket::SSL` and `AnyEvent` Perl modules must be installed as follows:

* For Debian/Ubuntu based distributions:

      sudo apt-get install libio-socket-ssl-perl libanyevent-perl

* For RedHat/Fedora/CentOS based distributions:

      sudo dnf install perl-IO-Socket-SSL perl-AnyEvent

* For Linux distributions without precompiled Perl module packages:

      sudo cpan IO::Socket::SSL AnyEvent

Build process
=============

The build process is only required if you want to modify the source code and regenerate the binaries or the packaged Perl script.

Prerequisites
-------------

In addition to the prerequisites listed above, the build process requires following dependencies:
* `PAR::Packer` Perl module (to build the binaries)
* `App::FatPacker` Perl module (to generate the packed Perl script)
* Optional: `EV` Perl module (to include and use the high performance `libev` backend for `AnyEvent`)

### Installing prerequisite on Windows

    cpanm EV

### Installing prerequisites on Linux

* For Debian/Ubuntu based distributions:

      sudo apt-get install libpar-packer-perl libapp-fatpacker-perl libev-perl

* For RedHat/Fedora/CentOS based distributions:

      sudo dnf install perl-PAR-Packer perl-App-FatPacker perl-EV

* For Linux distributions without precompiled Perl module packages:

      sudo cpan PAR::Packer App::FatPacker EV

Dependencies
------------

Following Perl modules must be placed in the `lib` subdirectory of the project:
* [RsaCertPem.pm](https://github.com/Yaribz/RsaCertPem/raw/main/RsaCertPem.pm)
* [SpringLobbyProtocol.pm](https://github.com/Yaribz/SpringLobbyProtocol/raw/main/SpringLobbyProtocol.pm)
* [SpringLobbyServer.pm](https://github.com/Yaribz/SpringLobbyServer/raw/main/SpringLobbyServer.pm)

Build commands
--------------

### Build command for Windows binary `springLobbyLanSrv.exe`

    pp -M IO::Socket::SSL -l libcrypto-3-x64__.dll -l libssl-3-x64__.dll -l zlib1__.dll -o springLobbyLanSrv.exe springLobbyLanSrv.pl


### Build command for Linux binary `springLobbyLanSrv`

    pp -M IO::Socket::SSL -o springLobbyLanSrv springLobbyLanSrv.pl

### Build command for packaged Perl script `springLobbyLanSrv.pl`

    fatpack file springLobbyLanSrv.pl >springLobbyLanSrv.packed.pl
