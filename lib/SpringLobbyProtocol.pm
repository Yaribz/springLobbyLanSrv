# SpringLobbyProtocol (Perl module)
#
# Marshallers and unmarshallers for the SpringRTS lobby protocol.
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

package SpringLobbyProtocol;

use strict;
use warnings;

use utf8;

use Encode qw'encode decode FB_DEFAULT FB_CROAK LEAVE_SRC';
use Digest::MD5 "md5_base64";

use base 'Exporter';

our $VERSION='0.10';

our %EXPORT_TAGS = (
  client => [qw'marshallPasswd marshallClientCommand unmarshallServerCommand'],
  server => [qw'marshallServerCommand unmarshallClientCommand'],
  regex => [qw'REGEX_USERNAME REGEX_EMAIL REGEX_VERIFICATIONCODE REGEX_IPV4 REGEX_HOSTHASHES REGEX_COMPFLAGS REGEX_CHANNEL REGEX_BOOL REGEX_ENUM2 REGEX_PORT REGEX_MAXPLAYERS REGEX_INT32 REGEX_RANK REGEX_BATTLEID REGEX_SCRIPTPASSWD REGEX_SCRIPTTAGDEF REGEX_SCRIPTTAG REGEX_UNIT REGEX_NBSPEC REGEX_TEAMID REGEX_STARTRECT REGEX_BANDURATION REGEX_TAGPARAM'],
  int32 => [qw'INT32_MIN INT32_MAX INT32_RANGE UINT32_MAX UINT32_RANGE'],
    );
my @COMMON_FUNCTIONS=(qw'marshallClientStatus unmarshallClientStatus marshallBattleStatus unmarshallBattleStatus marshallBattleStatusEx unmarshallBattleStatusEx marshallColor unmarshallColor');
map {push(@{$EXPORT_TAGS{$_}},@COMMON_FUNCTIONS)} (qw'client server');
Exporter::export_ok_tags(keys %EXPORT_TAGS);

use constant {
  REGEX_USERNAME => qr'^[\w\[\]]{1,20}$',
  REGEX_EMAIL => qr'^[\w\.\!\#\$\%\&\*\+\-\/\=\{\}\~]{1,63}\@(?:[a-zA-Z0-9\-]{1,63}\.){1,5}[a-zA-Z]{1,63}$',
  REGEX_VERIFICATIONCODE => qr'^[a-zA-Z\d]*$',
  REGEX_IPV4 => qr'^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$',
  REGEX_HOSTHASHES => qr'^(\d{1,10})(?: ([\da-fA-F]{1,16}))?$',
  REGEX_COMPFLAGS => qr'^[a-zA-Z]{1,20}(?: [a-zA-Z]{1,20}){1,20}$',
  REGEX_CHANNEL => qr'^[a-zA-Z\d_]{1,20}$',
  REGEX_BOOL => qr'^[01]$',
  REGEX_ENUM2 => qr'^[012]$',
  REGEX_PORT => qr'^(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{1,3}|\d)$',
  REGEX_MAXPLAYERS => qr'^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?)$',
  REGEX_INT32 => qr'^\-?\d{1,10}$',
  REGEX_RANK => qr'^[0-7]$',
  REGEX_BATTLEID => qr'^[1-9]\d{0,9}$',
  REGEX_SCRIPTPASSWD => qr'^[\w\d]{0,50}$',
  REGEX_SCRIPTTAGDEF => qr'^([\w\[\]\d\/\.]{1,100})\=(.{0,1024})$',
  REGEX_SCRIPTTAG => qr'^[\w\[\]\d\/\.]{1,100}$',
  REGEX_UNIT => qr'^\w{1,50}$',
  REGEX_NBSPEC => qr'^\d{1,10}$',
  REGEX_TEAMID => qr'^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$',
  REGEX_STARTRECT => qr'^(?:200|1\d\d|[1-9]\d|\d)$',
  REGEX_BANDURATION => qr '^\d{1,10}[hdwmy]?$',
  REGEX_TAGPARAM => qr'^([\w\.]{1,100})\=(.{1,1024})$',

  INT32_MIN => -2147483648,
  INT32_MAX => 2147483647,
  INT32_RANGE => 2147483648,
  UINT32_MAX => 4294967295,
  UINT32_RANGE => 4294967296,
};

my %CLIENT_CMD_SENTENCE_POS = (
  REQUESTUPDATEFILE => [1],
  LOGIN => [5,2],
  CHANNELTOPIC => [2],
  FORCELEAVECHANNEL => [3],
  SAY => [2],
  SAYEX => [2],
  SAYPRIVATE => [2],
  SAYPRIVATEEX => [2],
  OPENBATTLE => [9,4],
  UPDATEBATTLEINFO => [4],
  SAYBATTLE => [1],
  SAYBATTLEPRIVATE => [2],
  SAYBATTLEEX => [1],
  SAYBATTLEPRIVATEEX => [2],
  ADDBOT => [4],
  SCRIPT => [1],
  SETSCRIPTTAGS => [1,-1],
  JOINBATTLEDENY => [2],
  EXIT => [1],
  SAYFROM => [4],
  KICK => [2],
  BAN => [3],
  IGNORE => [1,-1],
  UNIGNORE => [1,-1],
  FRIENDREQUEST => [1,-1],
  ACCEPTFRIENDREQUEST => [1,-1],
  DECLINEFRIENDREQUEST => [1,-1],
  UNFRIEND => [1,-1],
  FRIENDREQUESTLIST => [1,-1],
    );

my %SERVER_CMD_SENTENCE_POS = (
  OK => [1],
  FAILED => [1],
  REGISTRATIONDENIED => [1],
  DENIED => [1],
  AGREEMENT => [1],
  RESETPASSWORDREQUESTDENIED => [1],
  RESETPASSWORDDENIED => [1],
  RESENDVERIFICATIONDENIED => [1],
  CHANGEEMAILREQUESTDENIED => [1],
  CHANGEEMAILDENIED => [1],
  MOTD => [1],
  OFFERFILE => [2,2],
  SERVERMSG => [1],
  SERVERMSGBOX => [1,1],
  ADDUSER => [4],
  JOINFAILED => [2],
  MUTELIST => [1],
  CHANNELTOPIC => [-1], # legacy clients expect timestamp
  CLIENTS => [2],
  LEFT => [3],
  FORCELEAVECHANNEL => [3],
  SAID => [3],
  SAIDEX => [3],
  SAYPRIVATE => [2],
  SAYPRIVATEEX => [2],
  SAIDPRIVATE => [2],
  SAIDPRIVATEEX => [2],
  BATTLEOPENED => [11,5],
  JOINBATTLEFAILED => [1],
  OPENBATTLEFAILED => [1],
  UPDATEBATTLEINFO => [5],
  SAIDBATTLE => [2],
  SAIDBATTLEEX => [2],
  BROADCAST => [1],
  ADDBOT => [6],
  MAPGRADESFAILED => [1],
  SCRIPT => [1],
  SETSCRIPTTAGS => [1,-1],
  CHANNELMESSAGE => [2],
  CHANNEL => [3],
  SAIDFROM => [3],
  IGNORE => [1,-1],
  UNIGNORE => [1,-1],
  IGNORELIST => [1,-1],
  FRIENDREQUEST => [1,-1],
  FRIEND => [1,-1],
  UNFRIEND => [1,-1],
  FRIENDREQUESTLIST => [1,-1],
  FRIENDLIST => [1,-1],
    );

my %CLIENT_CMD_NB_PARAMS=(
  PING => 0,
  EXIT => [0,1],
  STLS => 0,
  LISTCOMPFLAGS => 0,
  REGISTER => [2,3],
  LOGIN => [6,7],
  CONFIRMAGREEMENT => [0,1],
  RESETPASSWORDREQUEST => 1,
  RESETPASSWORD => 2,
  RESENDVERIFICATION => 1,
  CHANGEEMAILREQUEST => 1,
  CHANGEEMAIL => [1,2],
  RENAMEACCOUNT => 1,
  CHANGEPASSWORD => 2,
  MYSTATUS => 1,
  CHANNELS => 0,
  CHANNELTOPIC => 2,
  JOIN => [1,2],
  LEAVE => 1,
  SAY => 2,
  SAYEX => 2,
  SAYPRIVATE => 2,
  SAYPRIVATEEX => 2,
  OPENBATTLE => 13,
  JOINBATTLE => [1,3],
  JOINBATTLEACCEPT => 1,
  JOINBATTLEDENY => [1,2],
  LEAVEBATTLE => 0,
  KICKFROMBATTLE => 1,
  UPDATEBATTLEINFO => 4,
  MYBATTLESTATUS => 2,
  FORCESPECTATORMODE => 1,
  FORCETEAMNO => 2,
  FORCEALLYNO => 2,
  HANDICAP => 2,
  FORCETEAMCOLOR => 2,
  ADDBOT => 4,
  REMOVEBOT => 1,
  UPDATEBOT => 3,
  SETSCRIPTTAGS => [1,undef],
  REMOVESCRIPTTAGS => [1,undef],
  DISABLEUNITS => [1,undef],
  ENABLEUNITS => [1,undef],
  ENABLEALLUNITS => 0,
  ADDSTARTRECT => 5,
  REMOVESTARTRECT => 1,
  SCRIPTSTART => 0,
  SCRIPT => 1,
  SCRIPTEND => 0,
  SAYBATTLE => 1,
  SAYBATTLEEX => 1,
  SAYBATTLEPRIVATE => 2,
  SAYBATTLEPRIVATEEX => 2,
  RING => 1,
  GETUSERINFO => [0,1],
  FORCELEAVECHANNEL => [2,3],
  KICK => [1,2],
  SETBOTMODE => 2,
  CREATEBOTACCOUNT => 2,
  BAN => [1,3],
  UNBAN => 1,
  LISTBANS => 0,
  SETACCESS => 2,
  DELETEACCOUNT => 1,
  IGNORE => [1,2],
  UNIGNORE => [1],
  IGNORELIST => 0,
  FRIENDREQUEST => [1,2],
  ACCEPTFRIENDREQUEST => 1,
  DECLINEFRIENDREQUEST => 1,
  UNFRIEND => 1,
  FRIENDREQUESTLIST => [0,1], # optional type
  FRIENDLIST => 0,
    );

my %SERVER_CMD_NB_PARAMS=(
  TASSERVER => 4,
  PONG => 0,
  REGISTRATIONDENIED => 1,
  REGISTRATIONACCEPTED => 0,
  ACCEPTED => 1,
  DENIED => 1,
  LOGININFOEND => 0,
  AGREEMENT => 1,
  AGREEMENTEND => 0,
  MOTD => 1,
  CHANGEEMAILREQUESTACCEPTED => 0,
  CHANGEEMAILREQUESTDENIED => 1,
  CHANGEEMAILACCEPTED => 0,
  CHANGEEMAILDENIED => 1,
  RESENDVERIFICATIONACCEPTED => 0,
  RESENDVERIFICATIONDENIED => 1,
  RESETPASSWORDREQUESTACCEPTED => 0,
  RESETPASSWORDREQUESTDENIED => 1,
  RESETPASSWORDACCEPTED => 0,
  RESETPASSWORDDENIED => 1,
  ADDUSER => 4,
  REMOVEUSER => 1,
  SERVERMSG => 1,
  SERVERMSGBOX => [1,2], # optional url
  CHANNEL => [2,3], # optional topic
  ENDOFCHANNELS => 0,
  CHANNELTOPIC => [3,4], # legacy clients expect timestamp
  CLIENTS => 2,
  JOINED => 2,
  LEFT => [2,3], # optional reason
  JOIN => 1,
  JOINFAILED => 2,
  FORCELEAVECHANNEL => [2,3], # optional reason
  CHANNELMESSAGE => 2,
  SAID => 3,
  SAIDEX => 3,
  SAYPRIVATE => 2,
  SAIDPRIVATE => 2,
  SAYPRIVATEEX => 2,
  SAIDPRIVATEEX => 2,
  OPENBATTLE => 1,
  OPENBATTLEFAILED => 1,
  BATTLEOPENED => [15,16], # additional channel parameter for new clients ("u" compat flag)
  BATTLECLOSED => 1,
  JOINBATTLE => [2,3], # additional channel parameter for new clients ("u" compat flag)
  JOINBATTLEREQUEST => 2,
  JOINBATTLEFAILED => 1,
  JOINEDBATTLE => [2,3], # optional scriptPassword
  LEFTBATTLE => 2,
  UPDATEBATTLEINFO => 5,
  SAIDBATTLE => 2,
  SAIDBATTLEEX => 2,
  CLIENTSTATUS => 2,
  CLIENTBATTLESTATUS => 3,
  REQUESTBATTLESTATUS => 0,
  KICKFROMBATTLE => 2,
  FORCEQUITBATTLE => 0,
  DISABLEUNITS => [1,undef],
  ENABLEUNITS => [1,undef],
  ENABLEALLUNITS => 1,
  RING => 1,
  ADDBOT => 6,
  REMOVEBOT => 2,
  UPDATEBOT => 4,
  ADDSTARTRECT => 5,
  REMOVESTARTRECT => 1,
  SCRIPTSTART => 0,
  SCRIPT => 1,
  SCRIPTEND => 0,
  SETSCRIPTTAGS => [1,undef],
  REMOVESCRIPTTAGS => [1,undef],
  IGNORE => [1,2], # optional reason
  UNIGNORE => 1,
  IGNORELISTBEGIN => 0,
  IGNORELIST => [1,3], # optional reason and accountId
  IGNORELISTEND => 0,
  FRIENDREQUEST => [1,3], # optional msg and accountId
  FRIEND => [1,2], # optional accountId
  UNFRIEND => [1,2], # optional accountId
  FRIENDREQUESTLISTBEGIN => 0,
  FRIENDREQUESTLIST => [1,4], # optional msg, accountId, type
  FRIENDREQUESTLISTEND => 0,
  FRIENDLISTBEGIN => 0,
  FRIENDLIST => [1,2], # optional accountId
  FRIENDLISTEND => 0,
  COMPFLAGS => [1,undef],
  REDIRECT => [1,2], # port parameter is not supported by legacy clietns
  );

# Marshallers/unmarshallers ###################################################

sub marshallPasswd { return md5_base64(shift).'==' }

sub marshallClientStatus {
  return oct('0b'.$_[0]{bot}
             .$_[0]{access}
             .sprintf('%03b',$_[0]{rank})
             .$_[0]{away}
             .$_[0]{inGame});
}

sub unmarshallClientStatus {
  my @s=split('',sprintf('%07b',shift() % 128));
  return { bot => $s[0]+0,
           access => $s[1]+0,
           rank => oct('0b'.$s[2].$s[3].$s[4]),
           away => $s[5]+0,
           inGame => $s[6]+0 };
}

sub marshallBattleStatus {
  return oct('0b0000'
             .sprintf('%04b',$_[0]{side})
             .sprintf('%02b',$_[0]{sync})
             .'0000'
             .sprintf('%07b',$_[0]{bonus})
             .$_[0]{mode}
             .sprintf('%04b',$_[0]{team} & 15)
             .sprintf('%04b',$_[0]{id} & 15)
             .$_[0]{ready}
             .'0');
}

sub marshallBattleStatusEx {
  my $teamLow = $_[0]{team} & 15;
  my $teamHigh = $_[0]{team} >> 4;
  my $idLow = $_[0]{id} & 15;
  my $idHigh = $_[0]{id} >> 4;
  my $m=oct('0b'
            .sprintf('%04b',$teamHigh)
            .sprintf('%04b',$_[0]{side})
            .sprintf('%02b',$_[0]{sync})
            .sprintf('%04b',$idHigh)
            .sprintf('%07b',$_[0]{bonus})
            .$_[0]{mode}
            .sprintf('%04b',$teamLow)
            .sprintf('%04b',$idLow)
            .$_[0]{ready}
            .'0');
  return $m > INT32_MAX ? $m - UINT32_RANGE : $m;
}

sub unmarshallBattleStatus {
  my $bs=sprintf('%032b',shift() % INT32_RANGE);
  return { side => oct('0b'.substr($bs,4,4)),
           sync => oct('0b'.substr($bs,8,2)),
           bonus => oct('0b'.substr($bs,14,7)),
           mode => substr($bs,21,1)+0,
           team => oct('0b'.substr($bs,22,4)),
           id => oct('0b'.substr($bs,26,4)),
           ready => substr($bs,30,1)+0 };
}

sub unmarshallBattleStatusEx {
  my $bs=sprintf('%032b',shift() % UINT32_RANGE);
  return { side => oct('0b'.substr($bs,4,4)),
           sync => oct('0b'.substr($bs,8,2)),
           bonus => oct('0b'.substr($bs,14,7)),
           mode => substr($bs,21,1)+0,
           team => oct('0b'.substr($bs,0,4).substr($bs,22,4)),
           id => oct('0b'.substr($bs,10,4).substr($bs,26,4)),
           ready => substr($bs,30,1)+0 };
}

sub marshallColor { return ($_[0]{blue}*65536)+$_[0]{green}*256+$_[0]{red} }
sub unmarshallColor { return { red => $_[0] & 255, green => ($_[0] >> 8) & 255, blue => ($_[0] >> 16) & 255 } }

sub marshallClientCommand { marshallCommand(\%CLIENT_CMD_SENTENCE_POS,@_) }
sub marshallServerCommand { marshallCommand(\%SERVER_CMD_SENTENCE_POS,@_) }
sub unmarshallClientCommand { unmarshallCommand(\%CLIENT_CMD_SENTENCE_POS,\%CLIENT_CMD_NB_PARAMS,@_) }
sub unmarshallServerCommand { unmarshallCommand(\%SERVER_CMD_SENTENCE_POS,\%SERVER_CMD_NB_PARAMS,@_) }

sub marshallCommand {
  my ($r_sentencePos,$r_u,$cmdId)=@_;
  my @utf8=map {encode('UTF-8',$_,FB_DEFAULT|LEAVE_SRC)} @{$r_u};
  $r_u=\@utf8;
  my ($sentencePos,$addSentences);
  if(defined $r_sentencePos->{$r_u->[0]}) {
    ($sentencePos,$addSentences)=@{$r_sentencePos->{$r_u->[0]}};
    $sentencePos=$#{$r_u} if($sentencePos == -1);
  }
  my $marshalled;
  if($sentencePos && $#{$r_u} >= $sentencePos) {
    $marshalled=join(' ',map {s/ / /gr} @{$r_u}[0..$sentencePos-1]).' ';
    my $lastSentencePos = defined $addSentences ? $addSentences == -1 ? $#{$r_u}+1 : $sentencePos + $addSentences : $sentencePos;
    die "$r_u->[0] command expects $lastSentencePos parameters max, got $#{$r_u}\n" if($#{$r_u} > $lastSentencePos);
    if($#{$r_u} < $lastSentencePos) {
      $marshalled.=join("\t",map {s/\t/    /gr} @{$r_u}[$sentencePos..$#{$r_u}]);
    }else{
      $marshalled.=join("\t",(map {s/\t/    /gr} @{$r_u}[$sentencePos..$lastSentencePos-1]),$r_u->[-1]);
    }
  }else{
    $marshalled=join(' ',map {s/ / /gr} @{$r_u});
  }
  substr($marshalled,0,0,'#'.$cmdId.' ') if(defined $cmdId);
  return $marshalled."\cJ";
}

sub unmarshallCommand {
  my ($r_sentencePos,$r_nbParams,$bytes)=@_;
  my $m = eval {decode('UTF-8',$bytes,FB_CROAK)}
    // die "invalid UTF-8 string\n";
  my $cmdId;
  ($cmdId,$m)=($1,$2) if($m =~ /^\#(\d+) (.+)$/);
  die "invalid command \"$m\"\n" unless($m =~ /^([^ ]+)/);
  my $cmd=$1;
  my ($sentencePos,$addSentences);
  ($sentencePos,$addSentences)=@{$r_sentencePos->{$cmd}} if(defined $r_sentencePos->{$cmd});
  my $r_u;
  if($sentencePos) {
    my @words=split(/ /,$m,$sentencePos+1);
    if(@words == $sentencePos+1) {
      map {s/ / /g} @words[0..$#words-1];
      if($addSentences) {
        my @sentences=split(/\t/,pop(@words),$addSentences == -1 ? -1 : $addSentences+1);
        if(@sentences == $addSentences+1) {
          map {s/    /\t/g} @sentences[0..$#sentences-1];
        }else{
          map {s/    /\t/g} @sentences;
        }
        push(@words,@sentences);
      }
      $r_u=\@words;
    }else{
      $r_u=[map {s/ / /gr} @words];
    }
  }else{
    $r_u=[map {s/ / /gr} split(/ /,$m,-1)];
  }
  my $nbParams=$r_nbParams->{$cmd};
  if(defined $nbParams) {
    if(ref $nbParams) {
      die "invalid number of parameters for $cmd command\n"
          if((defined $nbParams->[0] && $#{$r_u} < $nbParams->[0])
             || (defined $nbParams->[1] && $#{$r_u} > $nbParams->[1]));
    }else{
      die "invalid number of parameters for $cmd command\n" unless($nbParams == $#{$r_u});
    }
  }
  return ($r_u,$cmdId);
}

1;
