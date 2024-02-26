# RsaCertPem (Perl module)
#
# Automatic generation and retrieval of persistent self-signed RSA
# certificate/key files in PEM format.
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

package RsaCertPem;

use warnings;
use strict;

use Net::SSLeay qw'RSA_F4 MBSTRING_ASC';

use base 'Exporter';

our $VERSION='0.10';

our @EXPORT_OK=(qw'getPemCertificate generateSelfSignedRsaCertPem');

my %DEFAULT_CERT_PARAMS=(
  keySize => 2048,
  keyExponent => RSA_F4,
  serial => 1,
  validityPeriod => 31536000,
  country => 'XX',
  org => 'Unknown',
  cn => 'localhost',
  hashFunction => 'sha256',
    );

sub getPemCertificate {
  my ($keyFile,$certFile,%defaultCertParams)=@_;

  my ($keyPem,$certPem);
  if(! -f $keyFile || ! -f $certFile) {
    my $certGenError;
    ($keyPem,$certPem,$certGenError)=generateSelfSignedRsaCertPem(%defaultCertParams);
    die "Unable to generate self-signed certificate: $certGenError\n" if(defined $certGenError);
  
    open(my $keyHdl,'>',$keyFile)
        or die "Unable to open private key file \"$keyFile\" for writing - $!\n";
    print $keyHdl $keyPem;
    close($keyHdl);
    
    open(my $certHdl,'>',$certFile)
        or die "Unable to open certificate file \"$certFile\" for writing - $!\n";
    print $certHdl $certPem;
    close($certHdl);
  }else{
    open(my $keyHdl,'<',$keyFile)
        or die "Unable to open private key file \"$keyFile\" for reading - $!\n";
    $keyPem = do { local $/; <$keyHdl> };
    close($keyHdl);
    open(my $certHdl,'<',$certFile)
        or die "Unable to open certificate file \"$certFile\" for reading - $!\n";
    $certPem = do { local $/; <$certHdl> };
    close($certHdl);
  }

  return ($keyPem,$certPem);
}

sub generateSelfSignedRsaCertPem {
  my %certParams=@_;
  map {$certParams{$_}//=$DEFAULT_CERT_PARAMS{$_}} (keys %DEFAULT_CERT_PARAMS);

  my ($pKey,$cert);
  eval {
    $pKey=Net::SSLeay::EVP_PKEY_new()
        or die 'create EVP_PKEY structure';

    my $rsa=Net::SSLeay::RSA_generate_key($certParams{keySize},$certParams{keyExponent})
        or die 'generate RSA key pair';
    
    Net::SSLeay::EVP_PKEY_assign_RSA($pKey,$rsa)
        or die 'store RSA key pair in EVP_PKEY structure';

    $cert=Net::SSLeay::X509_new()
        or die 'create X.509 certificate structure';
    
    Net::SSLeay::ASN1_INTEGER_set(Net::SSLeay::X509_get_serialNumber($cert),$certParams{serial})
        or die 'set X.509 certificate serial';

    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notBefore($cert),0)
        or die 'adjust X.509 certificate validity period start';
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notAfter($cert),$certParams{validityPeriod})
        or die 'adjust X.509 certificate validity period end';

    Net::SSLeay::X509_set_pubkey($cert,$pKey)
        or die 'assign X.509 certificate public key';

    my $subjectName=Net::SSLeay::X509_get_subject_name($cert)
        or die 'retrieve X.509 certificate subject name';

    Net::SSLeay::X509_NAME_add_entry_by_txt($subjectName,'C',MBSTRING_ASC,$certParams{country})
        or die 'set X.509 certificate country code';
    Net::SSLeay::X509_NAME_add_entry_by_txt($subjectName,'O',MBSTRING_ASC,$certParams{org})
        or die 'set X.509 certificate organization';
    if(defined $certParams{ou}) {
      Net::SSLeay::X509_NAME_add_entry_by_txt($subjectName,'OU',MBSTRING_ASC,$certParams{ou})
          or die 'set X.509 certificate organization unit';
    }
    Net::SSLeay::X509_NAME_add_entry_by_txt($subjectName,'CN',MBSTRING_ASC,$certParams{cn})
        or die 'set X.509 certificate canonical name';

    Net::SSLeay::X509_set_issuer_name($cert,$subjectName)
        or die 'set X.509 certificate issuer name';

    my $hashFunction = Net::SSLeay::EVP_get_digestbyname($certParams{hashFunction})
        or die 'select X.509 hash function';
    
    Net::SSLeay::X509_sign($cert,$pKey,$hashFunction)
        or die 'sign X.509 certificate';

    1;
  } or do {
    my $errMsg=$@;
    Net::SSLeay::EVP_PKEY_free($pKey) if($pKey);
    Net::SSLeay::X509_free($cert) if($cert);
    return (undef,undef,'failed to '.$errMsg);
  };

  my $pemPrivateKey=Net::SSLeay::PEM_get_string_PrivateKey($pKey);
  Net::SSLeay::EVP_PKEY_free($pKey);
  
  my $pemCert=Net::SSLeay::PEM_get_string_X509($cert);
  Net::SSLeay::X509_free($cert);
  
  return ($pemPrivateKey,$pemCert);
}
