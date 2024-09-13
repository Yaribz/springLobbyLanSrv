#!/usr/bin/env perl
#
# springLobbyLanSrv.pl
#
# A Spring lobby server running in LAN mode, fast and easy to use
#
# Copyright (C) 2024  Yann Riou <yaribzh@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#

use warnings;
use strict;

use AnyEvent;
use File::Spec::Functions 'catfile';
use FindBin;
use Getopt::Long 2.3203 qw':config no_auto_abbrev no_getopt_compat bundling no_ignore_case';
use List::Util 'any';

use lib "$FindBin::Bin/lib";

use SpringLobbyProtocol;
use SpringLobbyServer;

use constant { MSWIN32 => $^O eq 'MSWin32' };

my $VERSION='0.11';

sub badUsage { warn $_[0]."\n" if(defined $_[0]); die "Invalid usage (see --help).\n" };

my %opt;
GetOptions(\%opt,qw'
           help|h
           version|v

           debug|d
           quiet|q

           address|a=s
           port|p=i
           wan|w=s
           no-wan|W
           country|c=s
           ')
    or badUsage();

foreach my $singleOption (qw'help version') {
  badUsage("The \"--$singleOption\" command line option cannot be used with other options.")
      if($opt{$singleOption} && keys %opt > 1);
}

if($opt{help}) {
  print <<EOH;

Usage:
  $FindBin::Script [options]
    
    Options:
      -a,--address <addr> : specify listening address (default: all)
      -c,--country <cc>   : specify country code assigned to clients
      -d,--debug          : show debug messages (very verbose)
      -h,--help           : print usage
      -p,--port <n>       : specify listening port (default: 8200)
      -q,--quiet          : remove output
      -v,--version        : print version
      -w,--wan <addr>     : force manual WAN address for LAN-to-WAN hosting
      -W,--no-wan         : disable support for LAN-to-WAN hosting through NAT
EOH
    print "\n" unless(MSWIN32);
    exit 0;
}

if($opt{version}) {
  my $anyEventModel=AnyEvent::detect();
  print "springLobbyLanSrv v$VERSION\n";
  print "  . AnyEvent v$AnyEvent::VERSION (event model: $anyEventModel)\n";
  print "  . Perl $^V\n";
  print "  . SpringLobbyProtocol v$SpringLobbyProtocol::VERSION\n";
  print "  . SpringLobbyServer v$SpringLobbyServer::VERSION\n";
  print "\n" unless(MSWIN32);
  exit 0;
}

my @incompatibleOptions=(
    ['debug','quiet'],
    ['wan','no-wan'],
    );
map {badUsage("Only one command line option allowed among \"--$_->[0]\" and \"--$_->[1]\".") if(defined $opt{$_->[0]} && defined $opt{$_->[1]})} @incompatibleOptions;

foreach my $addrOpt (qw'address wan') {
  badUsage("\"$opt{$addrOpt}\" is not a valid IPv4 address")
      if(defined $opt{$addrOpt} && ($opt{$addrOpt} !~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ || (any {$_ > 255} ($1,$2,$3,$4))));
}

badUsage("\"$opt{port}\" is not a valid port number")
    if(defined $opt{port} && $opt{port} > 65535);

badUsage("\"$opt{country}\" is not a valid country code")
    if(defined $opt{country} && $opt{country} !~ /^[a-zA-Z]{2}$/);

my %lobbySrvParams=(
  pemKeyFile => catfile($FindBin::Bin,'springLobbyLanSrv-key.pem'),
  pemCertFile => catfile($FindBin::Bin,'springLobbyLanSrv-cert.pem'),
  motd => [@{$SpringLobbyServer::DEFAULT_PARAMS{motd}},"The server is running springLobbyLanSrv v$VERSION."],
    );
$lobbySrvParams{debug}=1 if($opt{debug});
$lobbySrvParams{logger}=sub {} if($opt{quiet});
$lobbySrvParams{listenAddress}=$opt{address} if(defined $opt{address});
$lobbySrvParams{listenPort}=$opt{port} if(defined $opt{port});
if(defined $opt{wan}) {
  $lobbySrvParams{wanAddress}=$opt{wan};
}elsif($opt{'no-wan'}) {
  $lobbySrvParams{wanAddress}='';
}
$lobbySrvParams{defaultCountryCode}=uc($opt{country}) if(defined $opt{country});

my $lobbySrv=SpringLobbyServer->new(%lobbySrvParams);

AnyEvent->condvar()->recv();
