# SpringLobbyServer (Perl module)
#
# Extensible SpringRTS engine lobby server based on AnyEvent.
# Only the network protocol/logic is implemented, all database related
# operations (persistency, authentications etc.) must be implemented through
# callbacks.
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

########################################
#       Customization callbacks        #
########################################
# onNewClientConnection:
# ---------------------
#   Parameters:
#     $r_connInfo,$hdl
#   Return value:
#     $denyMsg (undef if allowed)
#   Processing:
#     should update $r_connInfo "country" field
########################################
# onAdditionalInGameTime:
# ---------------------
#   Parameters:
#     $r_connInfo,$login,$r_userInfo,$additionalInGameTime
#   Return balue (async only):
#     $mustBroadcastUserStatus
#   Processing:
#     can update $r_userInfo->{status}{rank} in case of in-game time based ranks
########################################
# onChannelJoin:
# -------------
#   Parameters:
#     $r_connInfo,$login,$r_userInfo,$channel
#   Return value:
#     $denyMsg (undef if allowed)
########################################
# onChannelMsg:
# ------------
#   Parameters:
#     $r_connInfo,$login,$r_userInfo,$channel,$r_msg,$isExMsg
#   Return values:
#     $denyMsg (undef if allowed, empty string if silently denied)
#   Processing:
#     update $r_msg in place to modify the message
########################################
# onBattleJoin:
# ------------
#   Parameters:
#     $r_connInfo,$login,$r_userInfo,$battleFounderName,$r_battleFounderUserInfo,$battleId
#   Return value:
#     $denyMsg (undef if allowed)
########################################
# onBattleMsg:
# -----------
#   Parameters:
#     $r_connInfo,$login,$r_userInfo,$battleFounderName,$r_battleFounderUserInfo,$battleId,$r_msg,$isExMsg
#   Return values:
#     $denyMsg (undef if allowed, empty string if silently denied)
#   Processing:
#     update $r_msg in place to modify the message
########################################
# onPrivateMsg:
# ------------
#   Parameters:
#     $r_connInfo,$login,$r_userInfo,$recipient,$r_recipientUserInfo,$r_msg,$isExMsg,$isBattleMsg
#   Return values:
#     $denyMsg (undef if allowed, empty string if silently denied)
#   Processing:
#     update $r_msg in place to modify the message
########################################
# onChannelTopic(Async):
# ---------------------
#   Parameters:
#     ($r_callback,)$r_connInfo,$login,$r_userInfo,$channel,$r_topic
#   Return values:
#     $denyMsg (undef if allowed, empty string if silently denied)
#   Processing:
#     update $r_topic in place to modify the new channel topic
########################################
# registrationSvc:
# ---------------
#   Parameters:
#     Register mode:
#       $r_connInfo,$userName,$password,$email ($email = '' if not provided)
#     Agreement/email confirm mode:
#       $r_connInfo,$userName,$emailVerificationCode ($emailVerifCode = '' if not provided)
#   Return value:
#     $deniedReason (undef if allowed)
########################################
# authenticationSvc:
# -----------------
#   Parameters:
#     $r_connInfo,$userName,$password,$r_userInfo
#   Return value:
#     $deniedReason (undef if allowed)
#   Processing:
#     should update $r_userInfo fields such as:
#       status/{rank,access,bot}
#       accountId
#       pendingAgreement (if an agreement must be confirmed by user and/or email validated with code)
#       accessLevel
#       bypassMaxClients
#       inGameTime
#       emailAddress
#       registrationTs
#       lastLoginTs
#       ignoredAccounts       ( { <accountId> => {userName => $userName[, reason => $reason] } } )
#       friendAccounts        ( { <accountId> => <userName> } )
#       friendRequestsIn      ( { <accountId> => {userName => $userName[, msg => $msg] } } )
#       friendRequestsOut     ( { <accountId> => {userName => $userName[, msg => $msg] } } )
########################################
# accountManagementSvc{$command}:
# ------------------------------
#   Parameters:
#     $r_callback,$r_connInfo,<lobby cmd params...>
#       RESETPASSWORDREQUEST   $email
#       RESETPASSWORD          $email,$verificationCode
#     $r_callback,$r_connInfo,$login,$r_userInfo,<lobby cmd params...>
#       RESENDVERIFICATION     $email
#       CHANGEEMAILREQUEST     $newEmail
#       CHANGEEMAIL            $newEmail[,$verificationCode]
#       RENAMEACCOUNT          $newUserName
#       CHANGEPASSWORD         $oldPassword,$newPassword
#       GETUSERINFO            $userName
#       SETBOTMODE             $botName,$botMode
#       CREATEBOTACCOUNT       $botName,$ownerName
#       BAN                    $userName,$duration,$reason
#       UNBAN                  $userName
#       LISTBANS
#       SETACCESS              $userName,$accessMode
#       DELETEACCOUNT          $userName           (must also remove references from ban, ignore and friend data)
#   Return values (callback parameters):
#     CHANGEEMAIL,CHANGEPASSWORD, SETBOTMODE, BAN, SETACCESS, DELETEACCOUNT
#       $failedReason,$accountId
#     GETUSERINFO
#       $failedReason,$r_userInfo
#         {accountId, registrationTs, emailAddress, inGameTime, lastLoginTs, lobbyClient, macAddressHash, systemHash, accessLevel, country, lastIpAddr}
#     LISTBANS
#       $failedReason,$r_bans
#     _OTHERS_
#       $failedReason (undef if OK)
########################################
# ignoreSvc{$command}:
# --------------------
#   Parameters:
#     $r_callback,$r_connInfo,$login,$r_userInfo,<lobby cmd params...>
#       IGNORE                 $userName[,$reason]
#       UNIGNORE               $userName
#       IGNORELIST                       (useful to show correct names of offline users who renamed after ignoring user logged in, so ignoring user can unignore them)
#   Return values (callback parameters):
#     IGNORE, UNIGNORE
#       $failedReason,$accountId
#     IGNORELIST
#       $r_ignoreList   [{userName => $ignoredUserName[, reason => $ignoreReason][, accountId => $ignoredAccountId]},...]
########################################
# friendSvc{$command}:
# --------------------
#   Parameters:
#     $r_callback,$r_connInfo,$login,$r_userInfo,<lobby cmd params...>
#       FRIENDREQUEST         $userName[,$msg]                          (must ignore duplicate requests and ignored accounts, i.e. set $failedReason to "", and check nb friends and nb requests against maxFriendsByAccount)
#       ACCEPTFRIENDREQUEST   $userName
#       DECLINEFRIENDREQUEST  $userName
#       UNFRIEND              $userName
#       FRIENDREQUESTLIST     $isOutReq (useful to show correct names of offline users who renamed after target user logged in, so he can accept/decline them)
#       FRIENDLIST                      (useful to show correct names of offline users who renamed after friends logged in, so they can unfriend them)
#   Return values (callback parameters):
#     FRIENDREQUEST, ACCEPTFRIENDREQUEST, DECLINEFRIENDREQUEST, UNFRIEND
#       $failedReason,$friendAccountId
#     FRIENDREQUESTLIST
#       $r_friendRequestList [{userName => $friendName[, msg => $msg][, accountId => $friendAccountId,]},...]
#     FRIENDLIST
#       $r_friendList        [{userName => $friendName[, accountId => $friendAccountId]}]
########################################
# serverBots{$botName}{onPrivateMsg}:
# ----------------------------------
#   Parameters: $r_callback,$r_connInfo,$login,$r_userInfo,$privateMsg,$isExMsg ($r_connInfo = undef => msg from another server bot)
#   Return values: $r_responsePrivateMsgs (undef => no response)
########################################
# serverBots{$botName}{onChannelMsg}:
# ----------------------------------
#   Parameters: $r_callback,$r_connInfo,$login,$r_userInfo,$channel,$chanMsg,$isExMsg ($r_connInfo = undef => msg from another server bot)
#   Return values: ($r_responseChannelMsgs,$r_responsePrivateMsgs) (undef => no response)
########################################
# channelBots{$channel}{$botName}:
# -------------------------------
#   Parameters: $r_callback,$r_connInfo,$login,$r_userInfo,$channel,$chanMsg,$isExMsg ($r_connInfo = undef => msg from another server bot)
#   Return values: ($r_responseChannelMsgs,$r_responsePrivateMsgs) (undef => no response)
########################################

package SpringLobbyServer;

use warnings;
use strict;

use AnyEvent::Handle;
use AnyEvent::Socket;
use Carp 'croak';
use JSON::PP ();
use List::Util qw'all any none first reduce';
use Scalar::Util 'weaken';
use Socket qw'unpack_sockaddr_in inet_ntoa';

use RsaCertPem 'getPemCertificate';
use SpringLobbyProtocol qw':server :regex :int32';

our $VERSION='0.10';

use constant {
  IP_ADDR_LOOPBACK => 0,
  IP_ADDR_LAN => 1,
  IP_ADDR_WAN => 2,

  SRV_MODE_NORMAL => 0,
  SRV_MODE_LAN => 1,

  CNT_CHECK_ONLY => 1,
  CNT_INCR_ONLY => 2,
};

my @LOG_LEVELS=('[ CRITICAL ]','[ ERROR    ]','[ WARNING  ]','[ NOTICE   ]','[ INFO     ]','[ DEBUG    ]');

my %DEFAULT_PARAMS=(
  listenAddress => '0.0.0.0', # ('0' IPv4 wildcard, '::' IPv6 wildcard)
  listenPort => 8200,
  serverBannerCommand => 'TASSERVER',
  protocolVersion => '0.37',
  engineVersion => '*',
  natHelperPort => '8201', # (unimplemented)
  serverMode => SRV_MODE_LAN,
  accessFlagLevel => 100, # access level required to get lobby moderator/admin access flag (0: disable automatic lobby access flag based on access level)
  defaultCountryCode => '??',
  readTimeout => 45,
  writeTimeout => 60,
  maxReadQueue => 2048, # (maximum length of one lobby command)
  maxWriteQueue => 524288, # (maximum data queued for one connection, when client does not read the socket)
  autoCork => 0, # (0: try to write message instantly, 1: wait one event loop)
  noDelay => 1, # (0: enable Nagle algorithm, 1: disable Nagle algorithm)
  pemKeyFile => 'spring-lobby-server-key.pem',
  pemCertFile => 'spring-lobby-server-cert.pem',
  wanAddress => undef,
  logger => sub {
    my ($m,$l)=@_;
    my @time = localtime(); $time[4]++; @time = map(sprintf('%02d',$_),@time);
    my $timestamp = ($time[5]+1900).$time[4].$time[3].$time[2].$time[1].$time[0];
    my $level = $LOG_LEVELS[$l];
    print "$timestamp $level $m\n";
  },
  debug => 0,
  motd => [
    'Welcome, {USERNAME}!',
    'There are currently {CLIENTS} clients connected.',
    'The server is hosting {CHANNELS} chat channels and {BATTLES} battles.',
    'Server uptime is {UPTIME}.',
  ],
  onNewClientConnection => undef,
  onNewClientConnectionAsync => undef,
  onAdditionalInGameTime => undef,
  onAdditionalInGameTimeAsync => undef,
  onChannelJoin => undef,
  onChannelMsg => undef,
  onBattleJoin => undef,
  onBattleMsg => undef,
  onPrivateMsg => undef,
  onChannelTopic => undef,
  onChannelTopicAsync => undef,
  registrationSvc => undef,
  registrationSvcAsync => undef,
  authenticationSvc => undef,
  authenticationSvcAsync => undef,
  accountManagementSvc => {},
  ignoreSvc => {},
  friendSvc => {},
  channelTopics => {}, # ($channelName => { topic => $topic, author => $author })
  countersCleaningInterval => 60,
  maxChatMsgLength => 1024,   # maximum length of messages sent with SAY(EX)/SAYPRIVATE(EX)/SAYBATTLE(EX)/SAYBATTLEPRIVATE(EX) commands (in number of UTF8 characters)
  maxBattleScriptTags => 512, # maximum number of script tags that can be set in a battle lobby
  maxConnFailedLogin => 3,    # maximum number of failed login attempts before automatically closing the connection (0 = disabled)
  unauthentConnTimeout => 10, # maximum time in seconds a connection can stay up without successfully logging in (0 = disabled)
  maxIgnoresByAccount => 100, # maximum number of ignored users by account (0 = disabled)
  maxFriendsByAccount => 100, # maximum number of friends by account (0 = disabled)
  maxUnauthentByHost => 8,    # maximum number of simultaneous unauthenticated client connections by host (0 = disabled)
  maxClientsByHost => 4,      # maximum number of simultaneous unprivileged client connections by host (not counting accounts with bot or access flag, 0 = disabled)
  maxInputRateByUnauthent => [[1,4,1024],[10,16,4096]],                 # maximum rate of input commands/data on unauthenticated connection
  maxInputRateByClient => [[1,50,4096],[10,200,20480]],                 # maximum rate of input commands/data by non-bot connection
  maxInputRateByBot => [[1,1000,262144],[10,4000,524288]],              # maximum rate of input commands/data by bot connection
  maxInducedTrafficRateByClient => [[1,4000,131072],[10,16000,262144]], # maximum rate of commands/data induced by non-bot connection
  maxInducedTrafficRateByBot => [[1,8000,262144],[10,32000,524288]],    # maximum rate of commands/data induced by bot connection
  maxDbCmdRateByClient => [[1,3],[10,6]],                               # maximum rate of input commands triggering access to database by non-bot connection
  maxDbCmdRateByBot => [[1,6],[10,12]],                                 # maximum rate of input commands triggering access to database by bot connection
  maxLoginRateByAccount => [[10,3],[60,6]],                             # maximum rate of successful login operations by account
  maxRenameRateByAccount => [[86400,4]],                                # maximum rate of successful renaming operations by account
  maxFailedLoginRateByHost => [[10,3],[60,6]],                          # maximum rate of failed login attempt by host
  maxRegisterRateByHost => [[86400,4]],                                 # maximum rate of account registration by host
  maxFailedAgreementRateByHost => [[10,2]],                             # maximum rate of failed agreement confirmation by host
    );

my %DEFAULT_PARAMS_LAN_MODE=(
  maxConnFailedLogin => 0,
  unauthentConnTimeout => 0,
  maxIgnoresByAccount => 0,
  maxFriendsByAccount => 0,
  maxUnauthentByHost => 0,
  maxClientsByHost => 0,
  maxInputRateByUnauthent => [],
  maxInputRateByClient => [],
  maxInputRateByBot => [],
  maxInducedTrafficRateByClient => [],
  maxInducedTrafficRateByBot => [],
  maxDbCmdRateByClient => [],
  maxDbCmdRateByBot => [],
  maxLoginRateByAccount => [],
  maxRenameRateByAccount => [],
  maxFailedLoginRateByHost => [],
  maxRegisterRateByHost => [],
  maxFailedAgreementRateByHost => [],
    );

# REGISTER, LOGIN, CONFIRMAGREEMENT, RESETPASSWORDREQUEST, RESETPASSWORD, RESENDVERIFICATION can only be used when not logged in and therefore are not useful for DB commands flood protection.
# However, they are kept here for completness.
our %DATABASE_ACCESS_COMMANDS = map {$_ => 1} (
  qw'
  REGISTER
  LOGIN
  CONFIRMAGREEMENT
  RESETPASSWORDREQUEST
  RESETPASSWORD
  RESENDVERIFICATION

  CHANGEEMAILREQUEST
  CHANGEEMAIL

  CHANNELTOPIC
  RENAMEACCOUNT
  CHANGEPASSWORD
  GETUSERINFO
  SETBOTMODE
  CREATEBOTACCOUNT
  BAN
  UNBAN
  LISTBANS
  SETACCESS
  DELETEACCOUNT
  IGNORE
  UNIGNORE
  IGNORELIST
  FRIENDREQUEST
  ACCEPTFRIENDREQUEST
  DECLINEFRIENDREQUEST
  UNFRIEND
  FRIENDREQUESTLIST
  FRIENDLIST
  ');

our %CMDS=(
  PING => [0,\&hPing],
  EXIT => [0,\&hExit],
  LISTCOMPFLAGS => [0,\&hListCompFlags],
  STLS => [0,\&hStls],
  REGISTER => [0,\&hRegister],
  LOGIN => [0,\&hLogin],
  CONFIRMAGREEMENT => [0,\&hConfirmAgreement],
  RESETPASSWORDREQUEST => [0,\&hResetPasswordRequest],
  RESETPASSWORD => [0,\&hResetPassword],
  RESENDVERIFICATION => [0,\&hResendVerification],
  CHANGEEMAILREQUEST => [0,\&hChangeEmailRequest],
  CHANGEEMAIL => [0,\&hChangeEmail],
  RENAMEACCOUNT => [1,\&hRenameAccount],
  CHANGEPASSWORD => [1,\&hChangePassword],
  MYSTATUS => [1,\&hMyStatus],
  CHANNELS => [1,\&hChannels],
  JOIN => [1,\&hJoin],
  LEAVE => [1,\&hLeave],
  SAY => [1,\&hSay],
  SAYEX => [1,\&hSay],
  SAYPRIVATE => [1,\&hSayPrivate],
  SAYPRIVATEEX => [1,\&hSayPrivate],
  OPENBATTLE => [1,\&hOpenBattle],
  JOINBATTLE => [1,\&hJoinBattle],
  JOINBATTLEACCEPT => [1,\&hJoinBattleAccept],
  JOINBATTLEDENY => [1,\&hJoinBattleDeny],
  LEAVEBATTLE => [1,\&hLeaveBattle],
  KICKFROMBATTLE => [1,\&hKickFromBattle],
  MYBATTLESTATUS => [1,\&hMyBattleStatus],
  ADDBOT => [1,\&hAddBot],
  REMOVEBOT => [1,\&hRemoveBot],
  UPDATEBOT => [1,\&hUpdateBot],
  FORCESPECTATORMODE => [1,\&hForceSpectatorMode],
  FORCETEAMNO => [1,\&hForceTeamNo],
  FORCEALLYNO => [1,\&hForceAllyNo],
  HANDICAP => [1,\&hHandicap],
  FORCETEAMCOLOR => [1,\&hForceTeamColor],
  SETSCRIPTTAGS => [1,\&hSetScriptTags],
  REMOVESCRIPTTAGS => [1,\&hRemoveSCriptTags],
  DISABLEUNITS => [1,\&hDisableUnits],
  ENABLEUNITS => [1,\&hEnableUnits],
  ENABLEALLUNITS => [1,\&hEnableAllUnits],
  UPDATEBATTLEINFO => [1,\&hUpdateBattleInfo],
  ADDSTARTRECT => [1,\&hAddStartRect],
  REMOVESTARTRECT => [1,\&hRemoveStartRect],
  SAYBATTLE => [1,\&hSayBattle],
  SAYBATTLEEX => [1,\&hSayBattle],
  SAYBATTLEPRIVATE => [1,\&hSayBattlePrivate],
  SAYBATTLEPRIVATEEX => [1,\&hSayBattlePrivate],
  RING => [1,\&hRing],
  GETUSERINFO => [1,\&hGetUserInfo],
  IGNORE => [1,\&hIgnore],
  UNIGNORE => [1,\&hUnignore],
  IGNORELIST => [1,\&hIgnoreList],
  FRIENDREQUEST => [1,\&hFriendRequest],
  ACCEPTFRIENDREQUEST => [1,\&hAcceptFriendRequest],
  DECLINEFRIENDREQUEST => [1,\&hDeclineFriendRequest],
  UNFRIEND => [1,\&hUnfriend],
  FRIENDREQUESTLIST => [1,\&hFriendRequestList],
  FRIENDLIST => [1,\&hFriendList],
  CHANNELTOPIC => [100,\&hChannelTopic],
  FORCELEAVECHANNEL => [100,\&hForceLeaveChannel],
  KICK => [100,\&hKick],
  SETBOTMODE => [100,\&hSetBotMode],
  CREATEBOTACCOUNT => [100,\&hCreateBotAccount],
  BAN => [100,\&hBan],
  UNBAN => [100,\&hUnban],
  LISTBANS => [100,\&hListBans],
  SETACCESS => [200,\&hSetAccess],
  DELETEACCOUNT => [200,\&hDeleteAccount],
    );

our %IGNORED_CMDS; map {$IGNORED_CMDS{$_}=1} (qw'
                                             GETCHANNELMESSAGES

                                             c.user.list_relationships
                                             c.telemetry.update_client_property
                                             c.telemetry.log_client_event
                                             c.telemetry.upload_infolog');

my %DEFAULT_SRVBOT_INFO=(country => undef, cpu => 0, accountId => 0, lobbyClient => 'ServerBot');
my %DEFAULT_SRVBOT_STATUS=(inGame => 0, rank => 0, away => 0, access => 1, bot => 1);

my $SRVMSG_LOBBY_PROTOCOL_EXTENSIONS = '@PROTOCOL_EXTENSIONS@ '.JSON::PP::encode_json(
  {
    'sayBattlePrivate:multicast' => 1,
  }
    );

sub new {
  my ($this,%params)=@_;
  my $class = ref($this) || $this;
  
  my $self={};
  my @invalidParams;
  foreach my $param (keys %params) {
    if(exists $DEFAULT_PARAMS{$param}) {
      $self->{$param}=$params{$param};
    }else{
      push(@invalidParams,$param);
    }
  }
  croak 'Invalid contructor parameter'.(@invalidParams>1?'s':'').': '.join(', ',@invalidParams)
      if(@invalidParams);

  my %defaultParams=%DEFAULT_PARAMS;
  map {$defaultParams{$_}=$DEFAULT_PARAMS_LAN_MODE{$_}} (keys %DEFAULT_PARAMS_LAN_MODE)
      if(($self->{serverMode}//$DEFAULT_PARAMS{serverMode}) == SRV_MODE_LAN);
  
  map {$self->{$_}//=$defaultParams{$_}} (keys %defaultParams);
  croak 'Inconsistent server parameters: serverMode is NOT set to LAN mode, but there is NO registration service function defined'
      if($self->{serverMode} != SRV_MODE_LAN && ! defined $self->{registrationSvc} && ! defined $self->{registrationSvcAsync});
  
  $self->{banner} = join(' ',@{$self}{qw'serverBannerCommand protocolVersion engineVersion natHelperPort serverMode'})."\cJ";
  @{$self}{qw'privateKeyPem certPem'}=getPemCertificate(@{$self}{qw'pemKeyFile pemCertFile'});
  @{$self}{qw'connections connQueues users lcUsers accounts channels battles serverBots lcServerBots channelBots'}=({},{},{},{},{},{},{},{},{},{});
  $self->{nextBattleId}=1;
  $self->{startTime}=time;
  map {$self->{$_}={}} (qw'nbUnauthentByHost authentConnByHost');
  $self->{accountCounters}={login => {}, rename => {}};
  $self->{hostCounters}={FailedLogin => {}, Register => {}, FailedAgreement => {}};
  
  my $weakSelf=$self;
  weaken($weakSelf);

  my $anyEventModel=AnyEvent::detect();
  $self->{logger}("Running SpringLobbyServer v$VERSION with AnyEvent v$AnyEvent::VERSION (event model: $anyEventModel)",4);
  $self->{countersCleaner}=AE::timer($self->{countersCleaningInterval},$self->{countersCleaningInterval},sub {cleanPersistentCounters($weakSelf)});

  if(! defined $self->{wanAddress}) {
    AnyEvent::DNS::a('resolver1.opendns.com',
                     sub {
                       my $openDnsResolverAddr=$_[0];
                       if(defined $openDnsResolverAddr) {
                         AnyEvent::DNS->new(server => [AnyEvent::Socket::parse_address($openDnsResolverAddr)])->resolve(
                           'myip.opendns.com','a',sub {
                             return unless(defined $weakSelf);
                             if(defined $_[0] && @{$_[0]}) {
                               my $wanIpAddr=$_[0][4];
                               if($wanIpAddr =~ REGEX_IPV4) {
                                 $weakSelf->{logger}("WAN IP address: $wanIpAddr (auto-detected)",3);
                                 $weakSelf->{wanAddress}=$wanIpAddr;
                               }else{
                                 $weakSelf->{logger}("Failed to auto-detect WAN IP address (invalid IPv4 address \"$wanIpAddr\")",2);
                               }
                             }else{
                               $weakSelf->{logger}('Failed to auto-detect WAN IP address (invalid response from resolver)',2);
                             }
                           });
                       }else{
                         $weakSelf->{logger}('Failed to auto-detect WAN IP address (unable to contact resolver)',2);
                       }
                     });
  }
  $self->{tcpServer}=tcp_server($self->{listenAddress},$self->{listenPort},sub {onNewClientConnection($weakSelf,@_)});
  $self->{logger}("Spring lobby server listening on $self->{listenAddress}:$self->{listenPort}",3);
  
  bless($self,$class);
  return $self;
}

sub cleanPersistentCounters {
  my $self=shift;
  return unless(defined $self);
  my $currentTime=time();
  my $loginAccCountersPruneTime=$currentTime - reduce {$a > $b->[0] ? $a : $b->[0]} (0,@{$self->{maxLoginRateByAccount}});
  my $r_accountLoginCounters=$self->{accountCounters}{login};
  map {delete $r_accountLoginCounters->{$_} unless($r_accountLoginCounters->{$_}[1] > $loginAccCountersPruneTime)} (keys %{$r_accountLoginCounters});
  my $renameAccCountersPruneTime=$currentTime - reduce {$a > $b->[0] ? $a : $b->[0]} (0,@{$self->{maxRenameRateByAccount}});
  my $r_accountRenameCounters=$self->{accountCounters}{rename};
  map {delete $r_accountRenameCounters->{$_} unless($r_accountRenameCounters->{$_}[1] > $renameAccCountersPruneTime)} (keys %{$r_accountRenameCounters});
  foreach my $hostCounterType (qw'FailedLogin Register FailedAgreement') {
    my $hostCountersPruneTime=$currentTime - reduce {$a > $b->[0] ? $a : $b->[0]} (0,@{$self->{'max'.$hostCounterType.'RateByHost'}});
    my $r_countersByHost=$self->{hostCounters}{$hostCounterType};
    map {delete $r_countersByHost->{$_} unless($r_countersByHost->{$_}[1] > $hostCountersPruneTime)} (keys %{$r_countersByHost});
  }
}

sub onNewClientConnection {
  my ($self,$fh,$host,$port)=@_;
  $self->{debug} && $self->{logger}("New client connection request from [$host:$port]",5);
  if($self->{maxUnauthentByHost} && exists $self->{nbUnauthentByHost}{$host} && $self->{nbUnauthentByHost}{$host} >= $self->{maxUnauthentByHost}) {
    close($fh);
    $self->{debug} && $self->{logger}("Denying client connection from [$host:$port] (too many simultaneous unauthenticated connections)",5);
    return;
  }
  my $r_connInfo={host => $host, port => $port, country => $self->{defaultCountryCode}, connectTime => time};
  if(defined $self->{onNewClientConnection}) {
    my $denyMsg=$self->{onNewClientConnection}($r_connInfo,$fh);
    if(defined $denyMsg) {
      close($fh);
      $self->{debug} && $self->{logger}("Denying client connection from [$host:$port] ($denyMsg)",5);
      return;
    }
  }
  $self->{nbUnauthentByHost}{$host}++;
  if(defined $self->{onNewClientConnectionAsync}) {
    $self->{onNewClientConnectionAsync}(
      sub {
        my $denyMsg=shift;
        if(defined $denyMsg) {
          close($fh);
          $self->{debug} && $self->{logger}("Denying client connection from [$host:$port] ($denyMsg)",5);
          delete $self->{nbUnauthentByHost}{$host} unless(--$self->{nbUnauthentByHost}{$host} > 0);
        }else{
          allowedNewClientConnection($self,$fh,$r_connInfo),
        }
      },
      $r_connInfo,$fh,
        );
  }else{
    allowedNewClientConnection($self,$fh,$r_connInfo);
  }
}

sub allowedNewClientConnection {
  my ($self,$fh,$r_connInfo)=@_;
  my $connIdx=fileno($fh);
  my $weakSelf=$self;
  weaken($weakSelf);
  my $hdl; $hdl=AnyEvent::Handle->new(
    connIdx => $connIdx,
    fh => $fh,
    rtimeout => $self->{readTimeout},
    wtimeout => $self->{writeTimeout},
    rbuf_max => $self->{maxReadQueue},
    wbuf_max => $self->{maxWriteQueue},
    autocork => $self->{autoCork},
    no_delay => $self->{noDelay},
    on_starttls => sub {
      my ($tlsHdl,$success,$tlsError)=@_;
      if($success) {
        $tlsHdl->push_write($weakSelf->{banner});
      }else{
        closeClientConnection($weakSelf,$tlsHdl,'TLS handshake error',$tlsError,1);
      }
    },
    on_error => sub {
      my ($errorHdl,$isFatal,$errorMsg)=@_;
      my ($networkError,$errorDetails);
      if($! == Errno::ECONNRESET) {
        $networkError='connection reset by peer';
      }elsif($! == Errno::ENOSPC) {
        if(defined $errorHdl->{rbuf_max} && $errorHdl->{rbuf_max} < length($errorHdl->{rbuf})) {
          $networkError='maximum lobby command size exceeded';
        }elsif(defined $errorHdl->{wbuf_max} && $errorHdl->{wbuf_max} < length($errorHdl->{wbuf})) {
          $networkError='write queue overflow'
        }else{
          $networkError='network error';
          $errorDetails=$errorMsg;
        }
      }else{
        $networkError='network error';
        $errorDetails=$errorMsg;
      }
      closeClientConnection($weakSelf,$errorHdl,$networkError,$errorDetails,1);
    },
    on_eof => sub {closeClientConnection($weakSelf,$_[0],'connection closed by peer',undef,1)},
    on_rtimeout => sub {closeClientConnection($weakSelf,$_[0],'socket read timeout',undef,1)},
    on_wtimeout => sub {closeClientConnection($weakSelf,$_[0],'socket write timeout',undef,1)},
    on_read => sub {$_[0]->push_read(line => qr'\cM?\cJ+', sub {handleLobbyCmdFromClient($weakSelf,@_)})}, #skylobby puts several LF after STLS, TASClient puts CR before LF...
               );
  if($hdl) {
    $self->{debug} && $self->{logger}("Allowing client connection from [$r_connInfo->{host}:$r_connInfo->{port}]",5);
    $r_connInfo->{hdl}=$hdl;
    $r_connInfo->{ipAddrType}=getIpAddrType($r_connInfo->{host});
    $r_connInfo->{localIpAddr}=inet_ntoa((unpack_sockaddr_in(getsockname($fh)))[1]) if($r_connInfo->{ipAddrType} == IP_ADDR_LAN);
    $r_connInfo->{loginTimeout}=AE::timer($self->{unauthentConnTimeout},0,sub {return if($hdl->destroyed()); closeClientConnection($weakSelf,$hdl,'login timeout',undef,1)}) if($self->{unauthentConnTimeout});
    $r_connInfo->{inputRateCounters}=[undef,undef];
    $self->{connections}{$connIdx}=$r_connInfo;
    $hdl->push_write($self->{banner});
  }else{
    $self->{logger}("Failed to accept client connection from [$r_connInfo->{host}:$r_connInfo->{port}]: $!",1);
  }
}

sub closeClientConnection {
  my ($self,$hdl,$reason,$details,$skipQueueDrain)=@_;
  return if(exists $self->{closeClientConnectionInProgress}); # avoid recursive call to closeClientConnection (may happen when draining queue below)
  my $connIdx=$hdl->{connIdx};
  my $r_connInfo = delete $self->{connections}{$connIdx};
  my $host=$r_connInfo->{host};
  my $login=$r_connInfo->{login};
  if($self->{debug}) {
    my $detailsStr = defined $details ? ' ('.$details.')' : '';
    $self->{logger}('Removing connection of client'.(defined $login ? " \"$login\"" : '')." [$host:$r_connInfo->{port}]: $reason$detailsStr",5);
  }
  if(defined $login) {
    my $r_userInfo = delete $self->{users}{$login};
    my $accountId=$r_userInfo->{accountId};
    delete $self->{accounts}{$accountId} if($accountId);
    delete $self->{lcUsers}{lc($login)};
    my $r_channels=$self->{channels};
    my $channelLeftReason;
    if($reason eq 'quit') {
      $channelLeftReason='Quit: ';
      $channelLeftReason.=$details if(defined $details);
    }else{
      $channelLeftReason=$reason;
    }
    map {delete $r_channels->{$_}{$login}; %{$r_channels->{$_}} ? broadcastChannel($self,$_,'LEFT',$_,$login,$channelLeftReason) : delete $r_channels->{$_}} (keys %{$r_userInfo->{channels}});
    my $bId=$r_userInfo->{battle};
    if(defined $bId) {
      my $r_b=$self->{battles}{$bId};
      delete $r_b->{users}{$login};
      if($r_b->{founder} eq $login) {
        map {undef $self->{users}{$_}{battle}} (keys %{$r_b->{users}});
        delete $self->{battles}{$bId};
        broadcast($self,'BATTLECLOSED',$bId);
      }else{
        map {delete $r_b->{bots}{$_}; broadcastBattle($self,$bId,'REMOVEBOT',$bId,$_)} (grep {$r_b->{bots}{$_}{owner} eq $login} (keys %{$r_b->{bots}}));
        broadcast($self,'LEFTBATTLE',$bId,$login);
      }
    }
    broadcast($self,'REMOVEUSER',$login);
    my $r_hostConns=$self->{authentConnByHost}{$host};
    delete $r_hostConns->{$connIdx};
    delete $self->{authentConnByHost}{$host} unless(%{$r_hostConns});
  }else{
    delete $self->{nbUnauthentByHost}{$host} unless(--$self->{nbUnauthentByHost}{$host} > 0);
  }
  my $r_queuedMsgs=delete $self->{connQueues}{$connIdx};
  if(defined $r_queuedMsgs && ! $skipQueueDrain) {
    $self->{closeClientConnectionInProgress}=1;
    if($#{$r_queuedMsgs} == 0) {
      $hdl->push_write(${$r_queuedMsgs->[0]});
    }else{
      my $queueBuffer;
      $queueBuffer.=$$_ for (@{$r_queuedMsgs});
      $hdl->push_write($queueBuffer);
    }
    delete $self->{closeClientConnectionInProgress};
  }
  $hdl->destroy();
  return; # explicitely return undef to skip checkInducedTrafficFlood() call when using "return closeClientConnection()" idiom
}

sub getIpAddrType {
  my $ipAddr=shift;
  return IP_ADDR_LOOPBACK if(substr($ipAddr,0,4) eq '127.');
  return IP_ADDR_LAN if(substr($ipAddr,0,3) eq '10.' || substr($ipAddr,0,8) eq '192.168.' || ($ipAddr =~ /^172\.(\d+)\./ && $1 > 15 && $1 < 32));
  return IP_ADDR_WAN;
}

sub handleLobbyCmdFromClient {
  my ($self,$hdl,$line)=@_;
  if(! exists $self->{netMsgRcvTime}) {
    delete $self->{scheduledDispatcher};
    $self->{netMsgRcvTime}=time();
    AE::postpone {
      delete $self->{netMsgRcvTime};
      dispatchMessages($self);
    };
  }
  my $r_connInfo=$self->{connections}{$hdl->{connIdx}};
  my $login=$r_connInfo->{login};
  $self->{debug} && $self->{logger}('Received from'.(defined $login ? " \"$login\"" : '')." [$r_connInfo->{host}:$r_connInfo->{port}]: \"$line\"",5);
  return closeClientConnection($self,$hdl,'input flood')
      if(defined checkInputFlood($self,$r_connInfo,length($line)));
  my ($r_cmd,$cmdId) = eval { unmarshallClientCommand($line) };
  do { chomp($@); return closeClientConnection($self,$hdl,'protocol error',$@) } unless(defined $r_cmd);
  my $cmd=$r_cmd->[0];
  return closeClientConnection($self,$hdl,'protocol error','empty command') unless(defined $cmd);
  if(exists $CMDS{$cmd}) {
    if(defined $login) {
      my $r_userInfo=$self->{users}{$login};
      if($r_userInfo->{accessLevel} < $CMDS{$cmd}[0]) {
        $self->{logger}("Client \"$login\" [$r_connInfo->{host}:$r_connInfo->{port}] tried to call command \"$cmd\" with insuficient privileges",3);
      }else{
        return closeClientConnection($self,$hdl,'database access command flood')
            if(exists $DATABASE_ACCESS_COMMANDS{$cmd} && defined checkDbCmdFlood($self,$r_userInfo));
        my @inducedTraffic=$CMDS{$cmd}[1]->($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId);
        return if($hdl->destroyed());
        return closeClientConnection($self,$hdl,'induced traffic flood')
            if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      }
    }else{
      if($CMDS{$cmd}[0]) {
        closeClientConnection($self,$hdl,'protocol error','command requires authentication first');
      }else{
        $CMDS{$cmd}[1]->($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId);
      }
    }
  }elsif($IGNORED_CMDS{$cmd}) {
    $self->{debug} && $self->{logger}("Ignored command received from".(defined $login ? " \"$login\"" : '')." [$r_connInfo->{host}:$r_connInfo->{port}]: \"$cmd\"",5);
  }else{
    $self->{logger}("Unsupported command received from".(defined $login ? " \"$login\"" : '')." [$r_connInfo->{host}:$r_connInfo->{port}]: \"$cmd\"",3);
    closeClientConnection($self,$hdl,'protocol error','unknown command on unauthenticated connection') unless(defined $login);
  }
}

sub checkInputFlood {
  my ($self,$r_connInfo,$length)=@_;
  my $login=$r_connInfo->{login};
  my $r_thresholds;
  if(defined $login) {
    my $r_userStatus=$self->{users}{$login}{status};
    return undef if($r_userStatus->{access});
    $r_thresholds =  $self->{$r_userStatus->{bot} ? 'maxInputRateByBot' : 'maxInputRateByClient'};
  }else{
    $r_thresholds=$self->{maxInputRateByUnauthent};
  }
  my $r_rlData=$r_connInfo->{inputRateCounters};
  my $idxThresh=checkDataRateLimits($r_thresholds,$r_rlData,$self->{netMsgRcvTime},$length);
  return $idxThresh unless(defined $idxThresh && $self->{debug});
  my ($period,$maxCmds,$maxDataSize)=@{$r_thresholds->[$idxThresh]};
  my ($nbCmds,$dataSize)=@{$r_rlData->[0][$idxThresh][0]}[1,2];
  $self->{logger}('Input flood from'.(defined $login ? " \"$login\"" : '')." [$r_connInfo->{host}:$r_connInfo->{port}]: period=${period}s., cmd=$nbCmds/$maxCmds, data=$dataSize/$maxDataSize",5);
  return $idxThresh;
}

sub checkInducedTrafficFlood {
  my ($self,$r_userInfo,$nbEvents,$sumData)=@_;
  my $r_userStatus=$r_userInfo->{status};
  return undef if($r_userStatus->{access});
  my $r_thresholds =  $self->{$r_userStatus->{bot} ? 'maxInducedTrafficRateByBot' : 'maxInducedTrafficRateByClient'};
  my $idxThresh=checkDataRateLimitsMulti($r_thresholds,$r_userInfo->{inducedTrafficRateCounters},$self->{netMsgRcvTime}//time(),$nbEvents,$sumData);
  return $idxThresh unless(defined $idxThresh && $self->{debug});
  my ($period,$maxCmds,$maxDataSize)=@{$r_thresholds->[$idxThresh]};
  my ($nbCmds,$dataSize)=@{$r_userInfo->{inducedTrafficRateCounters}[0][$idxThresh][0]}[1,2];
  my $r_connInfo=$self->{connections}{$r_userInfo->{connIdx}};
  $self->{logger}("Induced traffic flood from \"$r_connInfo->{login}\" [$r_connInfo->{host}:$r_connInfo->{port}]: period=${period}s., cmd=$nbCmds/$maxCmds, data=$dataSize/$maxDataSize",5);
  return $idxThresh;
}

sub addInducedTraffic {
  my ($r_inducedTraffic,$nbEvents,$sumData)=@_;
  return unless($nbEvents);
  $r_inducedTraffic->[0]+=$nbEvents;
  $r_inducedTraffic->[1]+=$sumData;
}

sub checkDbCmdFlood {
  my ($self,$r_userInfo)=@_;
  my $r_userStatus=$r_userInfo->{status};
  return undef if($r_userStatus->{access});
  my $r_thresholds =  $self->{$r_userStatus->{bot} ? 'maxDbCmdRateByBot' : 'maxDbCmdRateByClient'};
  my $idxThresh=checkRateLimits($r_thresholds,$r_userInfo->{dbCmdCounters},$self->{netMsgRcvTime});
  return $idxThresh unless(defined $idxThresh && $self->{debug});
  my ($period,$maxCmds)=@{$r_thresholds->[$idxThresh]};
  my $nbCmds=$r_userInfo->{dbCmdCounters}[0][$idxThresh][0][1];
  my $r_connInfo=$self->{connections}{$r_userInfo->{connIdx}};
  $self->{logger}("Database access command flood from \"$r_connInfo->{login}\" [$r_connInfo->{host}:$r_connInfo->{port}]: period=${period}s., cmd=$nbCmds/$maxCmds",5);
  return $idxThresh;
}

sub checkAccountLoginFlood {
  my ($self,$r_userInfo,$login)=@_;
  return undef if($r_userInfo->{status}{access});
  my $accountIdOrLogin=$r_userInfo->{accountId} || $login;
  $self->{accountCounters}{login}{$accountIdOrLogin}//=[undef,undef];
  my $r_accLoginCounters=$self->{accountCounters}{login}{$accountIdOrLogin};
  my $idxThresh=checkRateLimits($self->{maxLoginRateByAccount},$r_accLoginCounters,$r_userInfo->{loginTime});
  return $idxThresh unless(defined $idxThresh && $self->{debug});
  my ($period,$maxLogins)=@{$self->{maxLoginRateByAccount}[$idxThresh]};
  my $nbLogins=$r_accLoginCounters->[0][$idxThresh][0][1];
  my $r_connInfo=$self->{connections}{$r_userInfo->{connIdx}};
  $self->{logger}("Login flood from \"$login\" [$r_connInfo->{host}:$r_connInfo->{port}]: period=${period}s., login=$nbLogins/$maxLogins",5);
  return $idxThresh;
}

sub checkAccountRenameFlood {
  my ($self,$r_userInfo,$currentTime,$partialMode)=@_;
  return undef if($r_userInfo->{status}{access});
  my $r_connInfo=$self->{connections}{$r_userInfo->{connIdx}};
  my $accountIdOrLogin=$r_userInfo->{accountId} || $r_connInfo->{login};
  if(! exists $self->{accountCounters}{rename}{$accountIdOrLogin}) {
    return if($partialMode == CNT_CHECK_ONLY);
    $self->{accountCounters}{rename}{$accountIdOrLogin}=[undef,undef];
  }
  my $r_accRenameCounters=$self->{accountCounters}{rename}{$accountIdOrLogin};
  my $idxThresh=checkRateLimits($self->{maxRenameRateByAccount},$r_accRenameCounters,$currentTime,$partialMode);
  return $idxThresh unless(defined $idxThresh && $self->{debug});
  my ($period,$maxRenames)=@{$self->{maxRenameRateByAccount}[$idxThresh]};
  my $nbRenames=$r_accRenameCounters->[0][$idxThresh][0][1];
  $self->{logger}("Rename flood from \"$r_connInfo->{login}\" [$r_connInfo->{host}:$r_connInfo->{port}]: period=${period}s., rename=$nbRenames/$maxRenames",5);
  return $idxThresh;
}

sub checkHostFlood {
  my ($self,$checkType,$host,$currentTime,$partialMode)=@_;
  my $r_countersByHost=$self->{hostCounters}{$checkType};
  if(! exists $r_countersByHost->{$host}) {
    return if($partialMode == CNT_CHECK_ONLY);
    $r_countersByHost->{$host}=[undef,undef];
  }
  my $r_hostCounters=$r_countersByHost->{$host};
  my $r_thresholds=$self->{'max'.$checkType.'RateByHost'};
  my $idxThresh=checkRateLimits($r_thresholds,$r_hostCounters,$currentTime,$partialMode);
  return $idxThresh unless(defined $idxThresh && $self->{debug});
  my ($period,$max)=@{$r_thresholds->[$idxThresh]};
  my $current=$r_hostCounters->[0][$idxThresh][0][1];
  $self->{logger}($checkType." flood from host \"$host\": $current/$max (period=${period}s.)",5);
  return $idxThresh;
}

######################################################################
# This function checks the counters before incrementing: it does NOT increment any counter if any threshold is reached.
#
# Rate limiter structures:
#
# $r_thresholds=[
#   [$period1,$maxEvents1],
#   [$period2,$maxEvents2],
#   ...
# ];
#
# $r_rlData:
#   0] $r_counters=[
#        [[$nextPeriodStart1,$currentNbEvents1],[$currentPeriodStart1,$oldNbEvents1]],
#        [[$nextPeriodStart2,$currentNbEvents2],[$currentPeriodStart2,$oldNbEvents2]],
#        ...
#      ];
#
#   1] $timestampLastUpdate
######################################################################
sub checkRateLimits {
  my ($r_thresholds,$r_rlData,$currentTime,$partialMode)=@_;
  my ($r_counters,$timestampLastUpdate)=@{$r_rlData};
  if(defined $timestampLastUpdate) {
    if($currentTime == $timestampLastUpdate) {
      if(! defined $partialMode || $partialMode == CNT_CHECK_ONLY) {
        my $firstMatchingThresh=first {$r_counters->[$_][0][1] >= $r_thresholds->[$_][1]} (0..$#{$r_thresholds});
        return $firstMatchingThresh if(defined $firstMatchingThresh);
        return undef if(defined $partialMode);
      }
      map {$_->[0][1]++} @{$r_counters};
    }else{
      if(! defined $partialMode || $partialMode == CNT_CHECK_ONLY) {
        my $firstMatchingThresh=first {$currentTime < $r_counters->[$_][0][0] && $r_counters->[$_][0][1] >= $r_thresholds->[$_][1]} (0..$#{$r_thresholds});
        return $firstMatchingThresh if(defined $firstMatchingThresh);
        return undef if(defined $partialMode);
      }
      for my $threshIdx (0..$#{$r_counters}) {
        my $r_counterData=$r_counters->[$threshIdx];
        if($currentTime < $r_counterData->[0][0]) {
          $r_counterData->[0][1]++;
        }else{
          pop(@{$r_counterData});
          unshift(@{$r_counterData},[$currentTime+$r_thresholds->[$threshIdx][0],1]);
        }
      }
    }
  }else{
    return undef if(defined $partialMode && $partialMode == CNT_CHECK_ONLY);
    $r_rlData->[0]=[map {[[$currentTime+$_->[0],1],[$currentTime,0]]} @{$r_thresholds}];
  }
  $r_rlData->[1]=$currentTime;
  return undef;
}

######################################################################
# This function checks the counters after incrementing: it always increments the counters.

# Data rate limiter structures:
#
# $r_thresholds=[
#   [$period1,$maxEvents1,$maxData1],
#   [$period2,$maxEvents2,$maxData2],
#   ...
# ]; # $period1 < $period2
#
# $r_rlData:
#   0] $r_counters=[
#        [[$nextPeriodStart1,$currentNbEvents1,$currentDataSize1],[$currentPeriodStart1,$oldNbEvents1,$oldDataSize1]],
#        [[$nextPeriodStart2,$currentNbEvents2,$currentDataSize2],[$currentPeriodStart2,$oldNbEvents2,$oldDataSize2]],
#        ...
#      ];
#
#   1] $timestampLastUpdate
######################################################################
sub checkDataRateLimits {
  my ($r_thresholds,$r_rlData,$currentTime,$newData)=@_;
  my ($r_counters,$timestampLastUpdate)=@{$r_rlData};
  $r_rlData->[1]=$currentTime;
  if(defined $timestampLastUpdate) {
    if($currentTime == $timestampLastUpdate) {
      map {$_->[0][1]++; $_->[0][2]+=$newData} @{$r_counters};
    }else{
      for my $threshIdx (0..$#{$r_counters}) {
        my $r_counterData=$r_counters->[$threshIdx];
        if($currentTime < $r_counterData->[0][0]) {
          $r_counterData->[0][1]++;
          $r_counterData->[0][2]+=$newData;
        }else{
          pop(@{$r_counterData});
          unshift(@{$r_counterData},[$currentTime+$r_thresholds->[$threshIdx][0],1,$newData]);
        }
      }
    }
    return first {$r_counters->[$_][0][1] > $r_thresholds->[$_][1] || $r_counters->[$_][0][2] > $r_thresholds->[$_][2]} (0..$#{$r_thresholds});
  }else{
    $r_rlData->[0]=[map {[[$currentTime+$_->[0],1,$newData],[$currentTime,0,0]]} @{$r_thresholds}];
    return first {$newData > $r_thresholds->[$_][2]} (0..$#{$r_thresholds});
  }
}

sub checkDataRateLimitsMulti {
  my ($r_thresholds,$r_rlData,$currentTime,$nbEvents,$sumData)=@_;
  my ($r_counters,$timestampLastUpdate)=@{$r_rlData};
  $r_rlData->[1]=$currentTime;
  if(defined $timestampLastUpdate) {
    if($currentTime == $timestampLastUpdate) {
      map {$_->[0][1]+=$nbEvents; $_->[0][2]+=$sumData} @{$r_counters};
    }else{
      for my $threshIdx (0..$#{$r_counters}) {
        my $r_counterData=$r_counters->[$threshIdx];
        if($currentTime < $r_counterData->[0][0]) {
          $r_counterData->[0][1]+=$nbEvents;
          $r_counterData->[0][2]+=$sumData;
        }else{
          pop(@{$r_counterData});
          unshift(@{$r_counterData},[$currentTime+$r_thresholds->[$threshIdx][0],$nbEvents,$sumData]);
        }
      }
    }
    return first {$r_counters->[$_][0][1] > $r_thresholds->[$_][1] || $r_counters->[$_][0][2] > $r_thresholds->[$_][2]} (0..$#{$r_thresholds});
  }else{
    $r_rlData->[0]=[map {[[$currentTime+$_->[0],$nbEvents,$sumData],[$currentTime,0,0]]} @{$r_thresholds}];
    return first {$nbEvents > $r_thresholds->[$_][1] || $sumData > $r_thresholds->[$_][2]} (0..$#{$r_thresholds});
  }
}

sub dispatchMessages {
  my $self=shift;
  while(my @queuedConns = keys %{$self->{connQueues}}) {
    foreach my $queuedConn (@queuedConns) {
      my $r_queuedMsgs=delete $self->{connQueues}{$queuedConn};
      if($#{$r_queuedMsgs} == 0) {
        $self->{connections}{$queuedConn}{hdl}->push_write(${$r_queuedMsgs->[0]});
      }else{
        my $queueBuffer;
        $queueBuffer.=$$_ for (@{$r_queuedMsgs});
        $self->{connections}{$queuedConn}{hdl}->push_write($queueBuffer);
      }
    }
  }
  $self->{scheduledDispatcher}=AE::timer(0.1,0,sub {dispatchMessages($self)});
}

# sendClient($self,$hdl,$r_aCmd[,$cmdId])
sub sendClient { return sendClientByIdx($_[0],$_[1]->{connIdx},$_[2],$_[3]) }

# sendClientByIdx($self,$connIdx,$r_aCmd[,$cmdId])
# called by: sendClient, sendUser, hJoinBattleDeny
sub sendClientByIdx {
  my $mCmd=marshallServerCommand($_[2],$_[3]);
  sendClientMarshalled($_[0],$_[1],\$mCmd);
  return (1,length($mCmd));
}

# sendClientMulti($self,$hdl,$r_aCmds[,$cmdId])
sub sendClientMulti { return sendClientMultiByIdx($_[0],$_[1]->{connIdx},$_[2],$_[3]) }

# sendClientMultiByIdx($self,$connIdx,$r_aCmds[,$cmdId])
sub sendClientMultiByIdx {
  my $mCmd;
  $mCmd.=$_ for (map {marshallServerCommand($_,$_[3])} @{$_[2]});
  sendClientMarshalled($_[0],$_[1],\$mCmd);
  return (1,length($mCmd)); # merged commands count as one network command (no network I/O overhead)
}

# sendClientMarshalled($self,$conndIdx,$r_sCmd)
# called by: sendClientByIdx, sendClientMulti, sendUserMarshalled
sub sendClientMarshalled {
  my ($self,$connIdx,$r_msg)=@_;
  if($self->{debug}) {
    my $r_connInfo=$self->{connections}{$connIdx};
    $self->{logger}('Sending to'.(defined $r_connInfo->{login} ? " \"$r_connInfo->{login}\"" : '')." [$r_connInfo->{host}:$r_connInfo->{port}]: \"".substr(${$r_msg},0,-1).'"',5);
  }
  push(@{$self->{connQueues}{$connIdx}},$r_msg);
}

# sendUser($self,$user,$r_aCmd[,$cmdId])
sub sendUser { return sendClientByIdx($_[0],$_[0]->{users}{$_[1]}{connIdx},$_[2],$_[3]) }

# sendUserMarshalled($self,$user,$r_sCmd)
# called by: broadcast, broadcastLegacy, broadcastChannel, broadcastChannelLegacy, broadcastBattle, broadcastBattleUFlag
sub sendUserMarshalled { sendClientMarshalled($_[0],$_[0]->{users}{$_[1]}{connIdx},$_[2]) }

sub broadcast {
  my $self=shift;
  my $mCmd=marshallServerCommand(\@_);
  map {sendUserMarshalled($self,$_,\$mCmd)} (keys %{$self->{users}});
  my $nbCmdsSent=keys %{$self->{users}};
  return ($nbCmdsSent,length($mCmd) * $nbCmdsSent);
}

sub broadcastLegacy {
  my $self=shift;
  my ($mCmd,$mCmdLegacy)=(marshallServerCommand($_[0]),marshallServerCommand($_[1]));
  my ($nbCmds,$nbCmdsLegacy)=(0,0);
  foreach my $userName (keys %{$self->{users}}) {
    if($self->{users}{$userName}{isLegacyClient}) {
      sendUserMarshalled($self,$userName,\$mCmdLegacy);
      ++$nbCmdsLegacy;
    }else{
      sendUserMarshalled($self,$userName,\$mCmd);
      ++$nbCmds;
    }
  }
  return ($nbCmds+$nbCmdsLegacy , $nbCmds*length($mCmd) + $nbCmdsLegacy*length($mCmdLegacy));
}

sub broadcastChannel {
  my ($self,$chan)=(shift,shift);
  if(exists $self->{channels}{$chan}) {
    my $mCmd=marshallServerCommand(\@_);
    map {sendUserMarshalled($self,$_,\$mCmd)} (keys %{$self->{channels}{$chan}});
    my $nbCmdsSent=keys %{$self->{channels}{$chan}};
    return ($nbCmdsSent,$nbCmdsSent*length($mCmd));
  }else{
    return (0,0);
  }
}

sub broadcastChannelLegacy {
  my ($self,$chan)=(shift,shift);
  if(exists $self->{channels}{$chan}) {
    my ($mCmd,$mCmdLegacy)=(marshallServerCommand($_[0]),marshallServerCommand($_[1]));
    my ($nbCmds,$nbCmdsLegacy)=(0,0);
    foreach my $userName (keys %{$self->{channels}{$chan}}) {
      if($self->{users}{$userName}{isLegacyClient}) {
        sendUserMarshalled($self,$userName,\$mCmdLegacy);
        ++$nbCmdsLegacy;
      }else{
        sendUserMarshalled($self,$userName,\$mCmd);
        ++$nbCmds;
      }
    }
    return ($nbCmds+$nbCmdsLegacy , $nbCmds*length($mCmd) + $nbCmdsLegacy*length($mCmdLegacy));
  }else{
    return (0,0);
  }
}

sub broadcastBattle {
  my ($self,$bId)=(shift,shift);
  my $mCmd=marshallServerCommand(\@_);
  map {sendUserMarshalled($self,$_,\$mCmd)} (keys %{$self->{battles}{$bId}{users}});
  my $nbCmdsSent=keys %{$self->{battles}{$bId}{users}};
  return ($nbCmdsSent,$nbCmdsSent*length($mCmd));
}

sub broadcastBattleUFlag {
  my ($self,$bId)=(shift,shift);
  my ($mCmdUFlag,$mCmd)=(marshallServerCommand($_[0]),marshallServerCommand($_[1]));
  my ($nbCmdsUFlag,$nbCmds)=(0,0);
  foreach my $userName (keys %{$self->{battles}{$bId}{users}}) {
    if($self->{users}{$userName}{compFlags}{u}) {
      sendUserMarshalled($self,$userName,\$mCmdUFlag);
      ++$nbCmdsUFlag;
    }else{
      sendUserMarshalled($self,$userName,\$mCmd);
      ++$nbCmds;
    }
  }
  return ($nbCmdsUFlag+$nbCmds,$nbCmdsUFlag*length($mCmdUFlag)+$nbCmds*length($mCmd));
}

sub broadcastChannelMsgToSrvBots {
  my ($self,$r_connInfo,$userName,$r_userInfo,$chan,$msg,$isExMsg)=@_;
  return unless(exists $self->{channelBots}{$chan});
  my $accountId=$r_userInfo->{accountId};
  foreach my $srvBot (keys %{$self->{channelBots}{$chan}}) {
    my $r_onSpecificChannelMsg=$self->{channelBots}{$chan}{$srvBot};
    my $r_onChannelMsg=$self->{serverBots}{$srvBot}{onChannelMsg};
    return unless(defined $r_onSpecificChannelMsg || defined $r_onChannelMsg);
    my $srvBotAccountId=$self->{serverBots}{$srvBot}{accountId};
    my $r_onChanMsgCb = sub {
      my ($r_chanMsgs,$r_pvMsgs)=@_;
      my $r_srvBotInfo=$self->{serverBots}{$srvBot};
      return unless(defined $r_srvBotInfo);
      AE::postpone {
        if(defined $r_chanMsgs && @{$r_chanMsgs} && exists $r_srvBotInfo->{channels}{$chan}) {
          foreach my $response (@{$r_chanMsgs}) {
            my ($responseMsg,$saidCmd,$useExMsg);
            if(ref $response eq '') {
              ($responseMsg,$saidCmd,$useExMsg)=($response,'SAID',0);
            }else{
              ($responseMsg,$saidCmd,$useExMsg)=($response->[0],'SAIDEX',1);
            }
            broadcastChannel($self,$chan,$saidCmd,$chan,$srvBot,$responseMsg);
            broadcastChannelMsgToSrvBots($self,undef,$srvBot,$r_srvBotInfo,$chan,$responseMsg,$useExMsg);
          }
        }
        if(defined $r_pvMsgs && @{$r_pvMsgs}) {
          my $recipient=getOnlineClientName($self,$accountId,$userName);
          if(defined $recipient) {
            return if($srvBotAccountId && exists $self->{users}{$recipient}{ignoredAccounts}{$srvBotAccountId});
            foreach my $response (@{$r_pvMsgs}) {
              my ($responseMsg,$saidPrivateCmd);
              if(ref $response eq '') {
                ($responseMsg,$saidPrivateCmd)=($response,'SAIDPRIVATE');
              }else{
                ($responseMsg,$saidPrivateCmd)=($response->[0],'SAIDPRIVATEEX');
              }
              sendUser($self,$recipient,[$saidPrivateCmd,$srvBot,$responseMsg]);
            }
          }elsif(exists $self->{serverBots}{$userName}) {
            foreach my $response (@{$r_pvMsgs}) {
              my ($responseMsg,$useExMsg);
              if(ref $response eq '') {
                ($responseMsg,$useExMsg)=($response,0);
              }else{
                ($responseMsg,$useExMsg)=($response->[0],1);
              }
              sendPrivateMsgToSrvBot($self,undef,$srvBot,$r_srvBotInfo,$userName,$responseMsg,$useExMsg);
            }
          }
        }
      };
    };
    $r_onSpecificChannelMsg->($r_onChanMsgCb,$r_connInfo,$userName,$r_userInfo,$chan,$msg,$isExMsg)
        if(defined $r_onSpecificChannelMsg);
    $r_onChannelMsg->($r_onChanMsgCb,$r_connInfo,$userName,$r_userInfo,$chan,$msg,$isExMsg)
        if(defined $r_onChannelMsg);
  }
}

sub sendPrivateMsgToSrvBot {
  my ($self,$r_connInfo,$userName,$r_userInfo,$srvBot,$msg,$isExMsg)=@_;
  return unless(exists $self->{serverBots}{$srvBot} && defined $self->{serverBots}{$srvBot}{onPrivateMsg});
  my $srvBotAccountId=$self->{serverBots}{$srvBot}{accountId};
  my $accountId=$r_userInfo->{accountId};
  $self->{serverBots}{$srvBot}{onPrivateMsg}(
    sub {
      my $r_pvMsgs=shift;
      return unless(defined $r_pvMsgs && @{$r_pvMsgs});
      my $r_srvBotInfo=$self->{serverBots}{$srvBot};
      return unless(defined $r_srvBotInfo);
      my $recipient;
      if($accountId) {
        $recipient=$self->{accounts}{$accountId};
      }elsif(exists $self->{users}{$userName}) {
        $recipient=$userName;
      }
      if(defined $recipient) {
        return if($srvBotAccountId && exists $self->{users}{$recipient}{ignoredAccounts}{$srvBotAccountId});
        foreach my $response (@{$r_pvMsgs}) {
          my ($responseMsg,$saidPrivateCmd);
          if(ref $response eq '') {
            ($responseMsg,$saidPrivateCmd)=($response,'SAIDPRIVATE');
          }else{
            ($responseMsg,$saidPrivateCmd)=($response->[0],'SAIDPRIVATEEX');
          }
          sendUser($self,$recipient,[$saidPrivateCmd,$srvBot,$responseMsg]);
        }
      }elsif(exists $self->{serverBots}{$userName}) {
        foreach my $response (@{$r_pvMsgs}) {
          my ($responseMsg,$useExMsg);
          if(ref $response eq '') {
            ($responseMsg,$useExMsg)=($response,0);
          }else{
            ($responseMsg,$useExMsg)=($response->[0],1);
          }
          sendPrivateMsgToSrvBot($self,undef,$srvBot,$r_srvBotInfo,$userName,$responseMsg,$useExMsg);
        }
      }
    },
    $r_connInfo,$userName,$r_userInfo,$msg,$isExMsg,
  );
}

# Following functions are called for each online user when a new battle is opened
#   $hostLanIpAddr is only provided if != '*'
#   $selfWanIpAddr is only provided if != '' (i.e. manual or successfully auto-detected WAN IP address)
sub getLoopbackBattleAddrForUser {
  my ($r_userConnInfo,$hostIpAddr,$hostLanIpAddr,$selfWanIpAddr)=@_;
  return $hostIpAddr if($r_userConnInfo->{ipAddrType} == IP_ADDR_LOOPBACK);
  return $r_userConnInfo->{localIpAddr} if($r_userConnInfo->{ipAddrType} == IP_ADDR_LAN);
  return $selfWanIpAddr // $hostLanIpAddr // $hostIpAddr;
}
sub getLanBattleAddrForUser {
  my ($r_userConnInfo,$hostIpAddr,undef,$selfWanIpAddr)=@_;
  return $hostIpAddr if($r_userConnInfo->{ipAddrType} == IP_ADDR_LOOPBACK || $r_userConnInfo->{ipAddrType} == IP_ADDR_LAN);
  return $selfWanIpAddr // $hostIpAddr;
}
sub getWanBattleAddrForUser {
  my ($r_userConnInfo,$hostIpAddr,$hostLanIpAddr)=@_;
  return $hostIpAddr if($r_userConnInfo->{ipAddrType} == IP_ADDR_LOOPBACK || $r_userConnInfo->{ipAddrType} == IP_ADDR_LAN);
  return $hostLanIpAddr if(defined $hostLanIpAddr && $r_userConnInfo->{host} eq $hostIpAddr);
  return $hostIpAddr;
}

# Following functions are called for each open battle when a new user logs in
#   $hostLanIpAddr is always provided (must be compared to '*' before use)
#   $selfWanIpAddr is only provided if != '' (i.e. manual or successfully auto-detected WAN IP address)
sub getBattleAddrForLoopbackUser { return $_[1] }
sub getBattleAddrForLanUser {
  my ($r_userConnInfo,$hostIpAddr,$hostIpAddrType)=@_;
  return $r_userConnInfo->{localIpAddr} if($hostIpAddrType == IP_ADDR_LOOPBACK);
  return $hostIpAddr;
}
sub getBattleAddrForWanUser {
  my ($r_userConnInfo,$hostIpAddr,$hostIpAddrType,$hostLanIpAddr,$selfWanIpAddr)=@_;
  if($hostIpAddrType == IP_ADDR_LOOPBACK) {
    return $selfWanIpAddr if(defined $selfWanIpAddr);
    return $hostLanIpAddr unless($hostLanIpAddr eq '*');
    return $hostIpAddr;
  }
  return $selfWanIpAddr // $hostIpAddr if($hostIpAddrType == IP_ADDR_LAN);
  return $hostLanIpAddr if($hostLanIpAddr ne '*' && $r_userConnInfo->{host} eq $hostIpAddr);
  return $hostIpAddr;
}

sub hPing {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  return sendClient($self,$hdl,['PONG'],$cmdId);
}

sub hExit {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  return closeClientConnection($self,$hdl,'quit',$r_cmd->[1],1);
}

sub hListCompFlags {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  return sendClient($self,$hdl,['COMPFLAGS','sp','b','u'],$cmdId);
}

sub hStls {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  return closeClientConnection($self,$hdl,'protocol error','duplicate STLS command') if($hdl->{tls});
  sendClient($self,$hdl,['OK','cmd=STLS'],$cmdId);
  my $r_queuedMsgs=delete $self->{connQueues}{$hdl->{connIdx}};
  if(defined $r_queuedMsgs) {
    if($#{$r_queuedMsgs} == 0) {
      $hdl->push_write(${$r_queuedMsgs->[0]});
    }else{
      my $queueBuffer;
      $queueBuffer.=$$_ for (@{$r_queuedMsgs});
      $hdl->push_write($queueBuffer);
    }
  }
  return if($hdl->destroyed());
  $hdl->starttls('accept',{cert => $self->{certPem}, key => $self->{privateKeyPem}});
  return; # no induced traffic check (command can only be used once)
}

sub hRegister {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  my (undef,$userName,$password,$email)=@{$r_cmd};
  $email//='';
  return closeClientConnection($self,$hdl,'protocol error','cannot register while already logged in')
      if(exists $r_connInfo->{login});
  return closeClientConnection($self,$hdl,'protocol error','invalid REGISTER parameter') unless(
    $userName =~ REGEX_USERNAME
    && length($password) < 50
    && ($email eq '' || ($email =~ REGEX_EMAIL && length($email) < 255)));
  return closeClientConnection($self,$hdl,'protocol error','duplicate REGISTER command')
      if(exists $r_connInfo->{asyncRegistrationInProgress});
  my $lcUserName=lc($userName);
  my $denyString = exists $self->{lcUsers}{$lcUserName} ? 'already in use.' : exists $self->{lcServerBots}{$lcUserName} ? 'reserved for internal use.' : undef;
  return sendClient($self,$hdl,['REGISTRATIONDENIED','Username is '.$denyString],$cmdId)
      if(defined $denyString);
  my $currentTime=$self->{netMsgRcvTime};
  if(defined checkHostFlood($self,'Register',$r_connInfo->{host},$currentTime,CNT_CHECK_ONLY)) {
    sendClient($self,$hdl,['REGISTRATIONDENIED','Too many registrations from this host, please try again later'],$cmdId);
    return closeClientConnection($self,$hdl,'too many registrations from this host');
  }
  if(defined $self->{registrationSvc}) {
    my $deniedReason=$self->{registrationSvc}($r_connInfo,$userName,$password,$email);
    return sendClient($self,$hdl,['REGISTRATIONDENIED',$deniedReason],$cmdId)
        if(defined $deniedReason);
  }
  if(defined $self->{registrationSvcAsync}) {
    $r_connInfo->{asyncRegistrationInProgress}=1;
    $self->{registrationSvcAsync}(
      sub {
        my $deniedReason=shift;
        if($hdl->destroyed()) {
          checkHostFlood($self,'Register',$r_connInfo->{host},$currentTime,CNT_INCR_ONLY)
              unless(defined $deniedReason);
          return;
        }
        delete $r_connInfo->{asyncRegistrationInProgress};
        if(defined $deniedReason) {
          sendClient($self,$hdl,['REGISTRATIONDENIED',$deniedReason],$cmdId);
        }else{
          checkHostFlood($self,'Register',$r_connInfo->{host},$currentTime,CNT_INCR_ONLY);
          sendClient($self,$hdl,['REGISTRATIONACCEPTED'],$cmdId);
        }
      },
      $r_connInfo,$userName,$password,$email,
    );
  }else{
    checkHostFlood($self,'Register',$r_connInfo->{host},$currentTime,CNT_INCR_ONLY);
    sendClient($self,$hdl,['REGISTRATIONACCEPTED'],$cmdId);
  }
}

sub hLogin {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  return closeClientConnection($self,$hdl,'protocol error','duplicate LOGIN command')
      if(exists $r_connInfo->{login} || exists $r_connInfo->{asyncAuthentInProgress} || exists $r_connInfo->{pendingLoginData});
  my (undef,$userName,$password,$cpu,$lanIpAddr,$lobbyClient,$hostHashes,$compFlags)=@{$r_cmd};
  $compFlags//='';
  my ($macAddressHash,$systemHash);
  return closeClientConnection($self,$hdl,'protocol error','invalid LOGIN parameter') unless(
    $userName =~ REGEX_USERNAME
    && length($password) < 50
    && $cpu =~ /^\d{1,9}$/
    && ($lanIpAddr eq '*' || $lanIpAddr =~ REGEX_IPV4)
    && length($lobbyClient) < 50
    && $hostHashes =~ REGEX_HOSTHASHES && do {$macAddressHash=$1; $systemHash=$2; 1}
    && $compFlags =~ REGEX_COMPFLAGS);
  my $lcUserName=lc($userName);
  my $denyReason = exists $self->{lcUsers}{$lcUserName} ? 'Already logged in' : exists $self->{lcServerBots}{$lcUserName} ? 'Username reserved for internal use' : undef;
  if(defined $denyReason) {
    sendClient($self,$hdl,['DENIED',$denyReason],$cmdId);
    closeClientConnection($self,$hdl,'too many failed login attempts from this connection')
        if(++$r_connInfo->{nbDeniedLogin} >= $self->{maxConnFailedLogin} && $self->{maxConnFailedLogin});
    return;
  }
  if(defined checkHostFlood($self,'FailedLogin',$r_connInfo->{host},$self->{netMsgRcvTime},CNT_CHECK_ONLY)) {
    sendClient($self,$hdl,['DENIED','Too many failed login attemps from this host, please try again later'],$cmdId);
    return closeClientConnection($self,$hdl,'too many failed login attempts from this host');
  }
  my %compFlagsHash;
  map {$compFlagsHash{$_}=1} split(/ /,$compFlags);
  my $connIdx=$hdl->{connIdx};
  my %userInfo=(
    country => $r_connInfo->{country},
    connIdx => $connIdx,
    password => $password,
    cpu => $cpu,
    lanIpAddr => $lanIpAddr,
    lobbyClient => $lobbyClient,
    macAddressHash => $macAddressHash,
    systemHash => $systemHash,
    compFlags => \%compFlagsHash,
    channels => {},
    battle => undef,
    status => {
      inGame => 0,
      rank => 0,
      away => 0,
      access => 0,
      bot => 0,
    },
    accountId => 0,
    pendingAgreement => [],
    accessLevel => 1,
    inGameTime => 0,
    emailAddress => undef,
    registrationTs => undef,
    lastLoginTs => time,
    ignoredAccounts => {},
    friendAccounts => {},
    friendRequestsIn => {},
    friendRequestsOut => {},
    isLegacyClient => substr($lobbyClient,0,9) eq 'TASClient',
    inducedTrafficRateCounters => [undef,undef],
    dbCmdCounters => [undef,undef],
    loginTime => $self->{netMsgRcvTime},
      );
  if(defined $self->{authenticationSvc}) {
    my $deniedReason=$self->{authenticationSvc}($r_connInfo,$userName,$password,\%userInfo);
    if(defined $deniedReason) {
      checkHostFlood($self,'FailedLogin',$r_connInfo->{host},$self->{netMsgRcvTime},CNT_INCR_ONLY);
      sendClient($self,$hdl,['DENIED',$deniedReason],$cmdId);
      closeClientConnection($self,$hdl,'too many failed login attempts from this connection')
          if(++$r_connInfo->{nbDeniedLogin} >= $self->{maxConnFailedLogin} && $self->{maxConnFailedLogin});
      return;
    }
  }
  if(defined $self->{authenticationSvcAsync}) {
    $r_connInfo->{asyncAuthentInProgress}=1;
    $self->{authenticationSvcAsync}(
      sub {
        return if($hdl->destroyed());
        delete $r_connInfo->{asyncAuthentInProgress};
        my $deniedReason=shift;
        if(defined $deniedReason) {
          checkHostFlood($self,'FailedLogin',$r_connInfo->{host},$userInfo{loginTime},CNT_INCR_ONLY);
          sendClient($self,$hdl,['DENIED',$deniedReason],$cmdId);
          closeClientConnection($self,$hdl,'too many failed login attempts from this connection')
              if(++$r_connInfo->{nbDeniedLogin} >= $self->{maxConnFailedLogin} && $self->{maxConnFailedLogin});
        }elsif(@{$userInfo{pendingAgreement}}) {
          if(defined checkHostFlood($self,'FailedAgreement',$r_connInfo->{host},$userInfo{loginTime},CNT_CHECK_ONLY)) {
            sendClient($self,$hdl,['DENIED','Too many failed agreement confirmations from this host, please try again later'],$cmdId);
            return closeClientConnection($self,$hdl,'too many failed agreement confirmations from this host');
          }
          delete $r_connInfo->{loginTimeout};
          sendClientMultiByIdx($self,$connIdx,[(map {['AGREEMENT',$_]} @{$userInfo{pendingAgreement}}),['AGREEMENTEND']]);
          $userInfo{pendingAgreement}=[];
          $r_connInfo->{pendingLoginData}={userName => $userName, userInfo => \%userInfo, lcUserName => $lcUserName};
        }else{
          delete $r_connInfo->{loginTimeout};
          hLogin_allowed($self,$hdl,$r_connInfo,$userName,\%userInfo,$lcUserName,$cmdId,1);
        }
      },
      $r_connInfo,$userName,$password,\%userInfo,
        );
  }elsif(@{$userInfo{pendingAgreement}}) {
    if(defined checkHostFlood($self,'FailedAgreement',$r_connInfo->{host},$self->{netMsgRcvTime},CNT_CHECK_ONLY)) {
      sendClient($self,$hdl,['DENIED','Too many failed agreement confirmations from this host, please try again later'],$cmdId);
      return closeClientConnection($self,$hdl,'too many failed agreement confirmations from this host');
    }
    delete $r_connInfo->{loginTimeout};
    sendClientMultiByIdx($self,$connIdx,[(map {['AGREEMENT',$_]} @{$userInfo{pendingAgreement}}),['AGREEMENTEND']]);
    $userInfo{pendingAgreement}=[];
    $r_connInfo->{pendingLoginData}={userName => $userName, userInfo => \%userInfo, lcUserName => $lcUserName};
  }else{
    delete $r_connInfo->{loginTimeout};
    hLogin_allowed($self,$hdl,$r_connInfo,$userName,\%userInfo,$lcUserName,$cmdId);
  }
}

sub hConfirmAgreement {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  my $verificationCode=$r_cmd->[1]//'';
  return closeClientConnection($self,$hdl,'protocol error','unexpected CONFIRMAGREEMENT command')
      unless(exists $r_connInfo->{pendingLoginData});
  return closeClientConnection($self,$hdl,'protocol error','invalid CONFIRMAGREEMENT parameter')
      unless($verificationCode =~ REGEX_VERIFICATIONCODE);
  my ($userName,$r_userInfo,$lcUserName)=@{$r_connInfo->{pendingLoginData}}{qw'userName userInfo lcUserName'};
  my $currentTime=$self->{netMsgRcvTime};
  if(defined $self->{registrationSvc}) {
    my $deniedReason=$self->{registrationSvc}($r_connInfo,$userName,$verificationCode);
    if(defined $deniedReason) {
      checkHostFlood($self,'FailedAgreement',$r_connInfo->{host},$currentTime,CNT_INCR_ONLY);
      sendClient($self,$hdl,['DENIED',$deniedReason],$cmdId);
      closeClientConnection($self,$hdl,'too many failed login attempts from this connection')
          if(++$r_connInfo->{nbDeniedLogin} >= $self->{maxConnFailedLogin} && $self->{maxConnFailedLogin});
      return;
    }
  }
  if(defined $self->{registrationSvcAsync}) {
    $self->{registrationSvcAsync}(
      sub {
        return if($hdl->destroyed());
        my $deniedReason=shift;
        if(defined $deniedReason) {
          checkHostFlood($self,'FailedAgreement',$r_connInfo->{host},$currentTime,CNT_INCR_ONLY);
          sendClient($self,$hdl,['DENIED',$deniedReason],$cmdId);
          closeClientConnection($self,$hdl,'too many failed login attempts from this connection')
              if(++$r_connInfo->{nbDeniedLogin} >= $self->{maxConnFailedLogin} && $self->{maxConnFailedLogin});
        }else{
          delete $r_connInfo->{pendingLoginData};
          hLogin_allowed($self,$hdl,$r_connInfo,$userName,$r_userInfo,$lcUserName,$cmdId,1)
              unless($r_userInfo->{isLegacyClient});
        }
      },
      $r_connInfo,$userName,$verificationCode,
        );
  }else{
    delete $r_connInfo->{pendingLoginData};
    hLogin_allowed($self,$hdl,$r_connInfo,$userName,$r_userInfo,$lcUserName,$cmdId,1)
        unless($r_userInfo->{isLegacyClient});
  }
}

sub hLogin_allowed {
  my ($self,$hdl,$r_connInfo,$userName,$r_userInfo,$lcUserName,$cmdId,$recheckDuplicates)=@_;
  return if($hdl->destroyed());
  delete $r_connInfo->{nbDeniedLogin};
  if($recheckDuplicates) {
    my $deniedReason = exists $self->{lcUsers}{$lcUserName} ? 'Already logged in' : exists $self->{lcServerBots}{$lcUserName} ? 'Username reserved for internal use' : undef;
    if(defined $deniedReason) {
      sendClient($self,$hdl,['DENIED',$deniedReason],$cmdId);
      return closeClientConnection($self,$hdl,'login denied',$deniedReason);
    }
  }
  my $r_userStatus=$r_userInfo->{status};
  $r_userStatus->{access}=1 if($self->{accessFlagLevel} && $r_userInfo->{accessLevel} >= $self->{accessFlagLevel});
  my $host=$r_connInfo->{host};
  if(exists $self->{authentConnByHost}{$host} && ! $r_userInfo->{bypassMaxClients} && ! $r_userStatus->{access} && ! $r_userStatus->{bot}) {
    my $nbHostClients=0;
    foreach my $connIdx (keys %{$self->{authentConnByHost}{$host}}) {
      my $connUser=$self->{connections}{$connIdx}{login}; # always defined for authenticated connections
      my $r_connUserInfo=$self->{users}{$connUser};
      next if($r_connUserInfo->{bypassMaxClients});
      my $r_connUserStatus=$r_connUserInfo->{status};
      next if($r_connUserStatus->{access} || $r_connUserStatus->{bot});
      $nbHostClients++;
    }
    if($self->{maxClientsByHost} && $nbHostClients >= $self->{maxClientsByHost}) {
      my $deniedReason='Too many simultaneous client connections originating from this host';
      sendClient($self,$hdl,['DENIED',$deniedReason],$cmdId);
      return closeClientConnection($self,$hdl,'login denied',$deniedReason);
    }
  }
  if(defined checkAccountLoginFlood($self,$r_userInfo,$userName)) {
    my $deniedReason='Account login flood';
    sendClient($self,$hdl,['DENIED',$deniedReason],$cmdId);
    return closeClientConnection($self,$hdl,'login denied',$deniedReason);
  }
  sendClient($self,$hdl,['ACCEPTED',$userName],$cmdId);
  my @legacyAddUserFields=(qw'country cpu');
  push(@legacyAddUserFields,'accountId') unless($self->{serverMode} == SRV_MODE_LAN);
  broadcastLegacy($self,['ADDUSER',$userName,@{$r_userInfo}{qw'country accountId lobbyClient'}],['ADDUSER',$userName,@{$r_userInfo}{@legacyAddUserFields}]);
  $r_userInfo->{marshalledStatus}=marshallClientStatus($r_userStatus);
  broadcast($self,'CLIENTSTATUS',$userName,$r_userInfo->{marshalledStatus}) if($r_userInfo->{marshalledStatus});
  $r_connInfo->{login}=$userName;
  $r_connInfo->{inputRateCounters}=[undef,undef]; # authenticated connections may use different check periods for input flood protection
  delete $self->{nbUnauthentByHost}{$host} unless(--$self->{nbUnauthentByHost}{$host} > 0);
  my $connIdx=$hdl->{connIdx};
  $self->{authentConnByHost}{$host}{$connIdx}=1;
  $self->{users}{$userName}=$r_userInfo;
  my $accountId=$r_userInfo->{accountId};
  $self->{accounts}{$accountId}=$userName if($accountId);
  $self->{lcUsers}{$lcUserName}=$userName;
  my @loginInfoCmds;
  push(@loginInfoCmds,['SERVERMSG',$SRVMSG_LOBBY_PROTOCOL_EXTENSIONS])
      if(length($r_userInfo->{lobbyClient}) > 6 && substr($r_userInfo->{lobbyClient},0,7) eq 'SPADS v');
  if(defined $self->{motd}) {
    my %motdPlaceholders=(
      USERNAME => $userName,
      CLIENTS => scalar keys %{$self->{connections}},
      CHANNELS => scalar keys %{$self->{channels}},
      BATTLES => scalar keys %{$self->{battles}},
      UPTIME => secToTime(time-$self->{startTime}),
        );
    my @motd=@{$self->{motd}};
    foreach my $motdString (@motd) {
      map {$motdString =~ s/\{$_\}/$motdPlaceholders{$_}/g} (keys %motdPlaceholders);
    }
    push(@loginInfoCmds,(map {['MOTD',$_]} @motd));
  }
  if($r_userInfo->{isLegacyClient}) {
    map {push(@loginInfoCmds,['ADDUSER',$_,@{$self->{serverBots}{$_}}{@legacyAddUserFields}])} (keys %{$self->{serverBots}});
    map {push(@loginInfoCmds,['ADDUSER',$_,@{$self->{users}{$_}}{@legacyAddUserFields}])} (keys %{$self->{users}});
  }else{
    map {push(@loginInfoCmds,['ADDUSER',$_,@{$self->{serverBots}{$_}}{qw'country accountId lobbyClient'}])} (keys %{$self->{serverBots}});
    map {push(@loginInfoCmds,['ADDUSER',$_,@{$self->{users}{$_}}{qw'country accountId lobbyClient'}])} (keys %{$self->{users}});
  }
  my $r_funcGetBattleAddrForUser =
      $r_connInfo->{ipAddrType} == IP_ADDR_LOOPBACK ? \&getBattleAddrForLoopbackUser :
      $r_connInfo->{ipAddrType} == IP_ADDR_LAN ? \&getBattleAddrForLanUser :
      \&getBattleAddrForWanUser;
  my $selfWanIpAddr = (defined $self->{wanAddress} && $self->{wanAddress} ne '') ? $self->{wanAddress} : undef;
  foreach my $bId (keys %{$self->{battles}}) {
    my $r_b=$self->{battles}{$bId};
    push(@loginInfoCmds,['BATTLEOPENED',$bId,@{$r_b}{qw'type natType founder'},
                         $r_funcGetBattleAddrForUser->($r_connInfo,@{$r_b}{qw'ipAddr ipAddrType lanIpAddr'},$selfWanIpAddr),
                         @{$r_b}{qw'port maxPlayers'},$r_b->{password} eq '' ? 0 : 1,
                         @{$r_b}{qw'rankLimit mapHash engineName engineVersion mapName title gameName'},
                         $r_userInfo->{compFlags}{u} ? '__battle__'.$bId : ()]);
    push(@loginInfoCmds,['UPDATEBATTLEINFO',$bId,@{$r_b}{qw'nbSpec locked mapHash mapName'}]);
    map {push(@loginInfoCmds,['JOINEDBATTLE',$bId,$_]) unless($_ eq $r_b->{founder})} (keys %{$r_b->{users}});
  }
  map {push(@loginInfoCmds,['CLIENTSTATUS',$_,$self->{serverBots}{$_}{marshalledStatus}]) if($self->{serverBots}{$_}{marshalledStatus})} (keys %{$self->{serverBots}});
  map {push(@loginInfoCmds,['CLIENTSTATUS',$_,$self->{users}{$_}{marshalledStatus}]) if($self->{users}{$_}{marshalledStatus})} (keys %{$self->{users}});
  push(@loginInfoCmds,['LOGININFOEND']);
  sendClientMultiByIdx($self,$connIdx,\@loginInfoCmds);
}

sub secToTime {
  my $sec=shift;
  my @units=qw'year day hour minute second';
  my @amounts=(gmtime $sec)[5,7,2,1,0];
  $amounts[0]-=70;
  my @strings;
  for my $i (0..$#units) {
    if($amounts[$i] == 1) {
      push(@strings,"1 $units[$i]");
    }elsif($amounts[$i] > 1) {
      push(@strings,"$amounts[$i] $units[$i]s");
    }
  }
  @strings=("0 second") unless(@strings);
  return $strings[0] if($#strings == 0);
  my $endString=pop(@strings);
  my $startString=join(", ",@strings);
  return "$startString and $endString";
}

sub hResetPasswordRequest {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  my $email=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid RESETPASSWORDREQUEST parameter')
      unless($email =~ REGEX_EMAIL && length($email) < 255);
  return closeClientConnection($self,$hdl,'protocol error','unexpected RESETPASSWORDREQUEST, already logged in')
      if(exists $r_connInfo->{login} || exists $r_connInfo->{pendingLoginData});
  return sendClient($self,$hdl,['RESETPASSWORDREQUESTDENIED','Feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{RESETPASSWORDREQUEST});
  $self->{accountManagementSvc}{RESETPASSWORDREQUEST}(
    sub {
      return if($hdl->destroyed());
      my $deniedReason=shift;
      if(defined $deniedReason) {
        sendClient($self,$hdl,['RESETPASSWORDREQUESTDENIED',$deniedReason],$cmdId);
      }else{
        sendClient($self,$hdl,['RESETPASSWORDREQUESTACCEPTED'],$cmdId);
      }
    },
    $r_connInfo,$email,
      );
}

sub hResetPassword {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  my (undef,$email,$verificationCode)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid RESETPASSWORD parameter')
      unless($email =~ REGEX_EMAIL && length($email) < 255
             && $verificationCode =~ REGEX_VERIFICATIONCODE);
  return closeClientConnection($self,$hdl,'protocol error','unexpected RESETPASSWORD, already logged in')
      if(exists $r_connInfo->{login} || exists $r_connInfo->{pendingLoginData});
  return sendClient($self,$hdl,['RESETPASSWORDDENIED','Feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{RESETPASSWORD});
  $self->{accountManagementSvc}{RESETPASSWORD}(
    sub {
      return if($hdl->destroyed());
      my $deniedReason=shift;
      if(defined $deniedReason) {
        sendClient($self,$hdl,['RESETPASSWORDDENIED',$deniedReason],$cmdId);
      }else{
        sendClient($self,$hdl,['RESETPASSWORDACCEPTED'],$cmdId);
      }
    },
    $r_connInfo,$email,$verificationCode,
      );
}

sub hResendVerification {
  my ($self,$hdl,$r_connInfo,undef,undef,$r_cmd,$cmdId)=@_;
  my $email=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid RESENDVERIFICATION parameter')
      unless($email =~ REGEX_EMAIL && length($email) < 255);
  return closeClientConnection($self,$hdl,'protocol error','unexpected RESENDVERIFICATION, agreement already accepted')
      if(exists $r_connInfo->{login});
  return closeClientConnection($self,$hdl,'protocol error','unexpected RESENDVERIFICATION, not logged in')
      unless(exists $r_connInfo->{pendingLoginData});
  return sendClient($self,$hdl,['RESENDVERIFICATIONDENIED','Feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{RESENDVERIFICATION});
  my ($login,$r_userInfo)=@{$r_connInfo->{pendingLoginData}}{qw'userName userInfo'};
  $self->{accountManagementSvc}{RESENDVERIFICATION}(
    sub {
      return if($hdl->destroyed());
      my $deniedReason=shift;
      if(defined $deniedReason) {
        sendClient($self,$hdl,['RESENDVERIFICATIONDENIED',$deniedReason],$cmdId);
      }else{
        sendClient($self,$hdl,['RESENDVERIFICATIONACCEPTED'],$cmdId);
      }
    },
    $r_connInfo,$login,$r_userInfo,$email,
      );
}

sub hChangeEmailRequest {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $email=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid CHANGEEMAILREQUEST parameter')
      unless($email =~ REGEX_EMAIL && length($email) < 255);
  if(exists $r_connInfo->{pendingLoginData}) {
    ($login,$r_userInfo)=@{$r_connInfo->{pendingLoginData}}{qw'userName userInfo'};
  }elsif(! defined $login) {
    return closeClientConnection($self,$hdl,'protocol error','unexpected CHANGEEMAILREQUEST, not logged in');
  }
  return sendClient($self,$hdl,['CHANGEEMAILREQUESTDENIED','Feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{CHANGEEMAILREQUEST});
  $self->{accountManagementSvc}{CHANGEEMAILREQUEST}(
    sub {
      return if($hdl->destroyed());
      my $deniedReason=shift;
      sendClient($self,$hdl,defined $deniedReason ? ['CHANGEEMAILREQUESTDENIED',$deniedReason] : ['CHANGEEMAILREQUESTACCEPTED'],$cmdId);
    },
    $r_connInfo,$login,$r_userInfo,$email,
  );
  return; # no induced traffic check (command is already limited by maxDbCmdRate)
}

sub hChangeEmail {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$email,$verificationCode)=@{$r_cmd};
  $verificationCode//='';
  return closeClientConnection($self,$hdl,'protocol error','invalid CHANGEEMAIL parameter')
      unless($email =~ REGEX_EMAIL && length($email) < 255
             && $verificationCode =~ REGEX_VERIFICATIONCODE);
  if(exists $r_connInfo->{pendingLoginData}) {
    ($login,$r_userInfo)=@{$r_connInfo->{pendingLoginData}}{qw'userName userInfo'};
  }elsif(! defined $login) {
    return closeClientConnection($self,$hdl,'protocol error','unexpected CHANGEEMAIL, not logged in');
  }
  return sendClient($self,$hdl,['CHANGEEMAILDENIED','Feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{CHANGEEMAIL});
  $self->{accountManagementSvc}{CHANGEEMAIL}(
    sub {
      my ($deniedReason,$updatedAccountId)=@_;
      if(defined $deniedReason) {
        return if($hdl->destroyed());
        sendClient($self,$hdl,['CHANGEEMAILDENIED',$deniedReason],$cmdId);
      }else{
        # client may have disconnected, reconnected and even renamed during async processing...
        my (undef,$r_currentInfo)=getOnlineClientData($self,$updatedAccountId,$login);
        $r_currentInfo->{emailAddress}=$email if(defined $r_currentInfo);
        return if($hdl->destroyed());
        sendClientMulti($self,$hdl,[['CHANGEEMAILACCEPTED'],['SERVERMSG','Your email address has been changed to '.$email]],$cmdId);
      }
    },
    $r_connInfo,$login,$r_userInfo,$email,$verificationCode,
  );
  return; # no induced traffic check (command is already limited by maxDbCmdRate)
}

sub hRenameAccount {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $userName=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid RENAMEACCOUNT parameter')
      unless($userName =~ REGEX_USERNAME);
  return sendClient($self,$hdl,['SERVERMSG','Cannot rename account, feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{RENAMEACCOUNT});
  return sendClient($self,$hdl,['SERVERMSG','Failed to rename to '.$userName.': You already have that username.'],$cmdId)
      if($userName eq $login);
  my $lcUserName=lc($userName);
  my $denyReason = (exists $self->{lcUsers}{$lcUserName} && $lcUserName ne lc($login)) ? 'name is already taken by an online client'
      : exists $self->{lcServerBots}{$lcUserName} ? 'name is reserved for internal use'
      : undef;
  my $currentTime=$self->{netMsgRcvTime};
  return sendClient($self,$hdl,['SERVERMSG','Rename denied: too many renames for this account'],$cmdId)
      if(defined checkAccountRenameFlood($self,$r_userInfo,$currentTime,CNT_CHECK_ONLY));
  $self->{accountManagementSvc}{RENAMEACCOUNT}(
    sub {
      return if($hdl->destroyed());
      my $failedReason=shift;
      if(defined $failedReason) {
        sendClient($self,$hdl,['SERVERMSG','Failed to rename to '.$userName.': '.$failedReason],$cmdId);
      }else{
        checkAccountRenameFlood($self,$r_userInfo,$currentTime,CNT_INCR_ONLY);
        sendClient($self,$hdl,['SERVERMSG','Your account has been renamed to '.$userName.'. Reconnect with the new username (you will now be automatically disconnected).'],$cmdId);
        closeClientConnection($self,$hdl,'renaming');
      }
    },
    $r_connInfo,$login,$r_userInfo,$userName,
  );
  return; # no induced traffic check (command is already limited by maxDbCmdRate)
}

sub hChangePassword {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$oldPassword,$newPassword)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid CHANGEPASSWORD parameter')
      unless(length($oldPassword) < 50 && length($newPassword) < 50);
  return sendClient($self,$hdl,['SERVERMSG','Cannot change password, feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{CHANGEPASSWORD});
  return sendClient($self,$hdl,['SERVERMSG','Failed to change password: new password must be different to current password.'],$cmdId)
      if($oldPassword eq $newPassword);
  return sendClient($self,$hdl,['SERVERMSG','Failed to change password: invalid password.'],$cmdId)
      unless($oldPassword eq $r_userInfo->{password});
  $self->{accountManagementSvc}{CHANGEPASSWORD}(
    sub {
      my ($failedReason,$updatedAccountId)=@_;
      if(defined $failedReason) {
        return if($hdl->destroyed());
        sendClient($self,$hdl,['SERVERMSG','Failed to change password: '.$failedReason],$cmdId);
      }else{
        # client may have disconnected, reconnected and even renamed during async processing...
        my (undef,$r_currentInfo)=getOnlineClientData($self,$updatedAccountId,$login);
        $r_currentInfo->{password}=$newPassword if(defined $r_currentInfo);
        return if($hdl->destroyed());
        sendClient($self,$hdl,['SERVERMSG','Password changed successfully.'],$cmdId);
      }
    },
    $r_connInfo,$login,$r_userInfo,$oldPassword,$newPassword,
  );
  return; # no induced traffic check (command is already limited by maxDbCmdRate)
}

sub getOnlineClientName {
  my ($self,$accountId,$userName)=@_;
  return $self->{accounts}{$accountId} if($accountId);
  return $userName if(exists $self->{users}{$userName});
  return undef;
}

sub getOnlineClientData {
  my ($self,$accountId,$userName)=@_;
  if($accountId) {
    my $onlineName=$self->{accounts}{$accountId};
    return defined $onlineName ? ($onlineName,$self->{users}{$onlineName}) : (undef,undef);
  }
  # if server is not using account IDs we have to rely on $userName directly, hoping no race conditions occured during async processing...
  my $r_onlineInfo=$self->{users}{$userName};
  return defined $r_onlineInfo ? ($userName,$r_onlineInfo) : (undef,undef);
}

sub hMyStatus {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $marshalledStatus=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid MYSTATUS parameter')
      unless($marshalledStatus =~ REGEX_INT32 && $marshalledStatus >= INT32_MIN && $marshalledStatus <= INT32_MAX);
  my $r_u=unmarshallClientStatus($marshalledStatus);
  return unless(any {$r_userInfo->{status}{$_} != $r_u->{$_}} (qw'inGame away'));
  my $gameDuration;
  if($r_u->{inGame} && ! $r_userInfo->{status}{inGame}) {
    $r_userInfo->{gameStartTimestamp}=time();
  }elsif(! $r_u->{inGame} && $r_userInfo->{status}{inGame} && defined $r_userInfo->{gameStartTimestamp}) {
    $gameDuration = time() - delete $r_userInfo->{gameStartTimestamp};
    $gameDuration=5400 if($gameDuration > 5400);
    $r_userInfo->{inGameTime}+=$gameDuration;
  }
  map {$r_userInfo->{status}{$_}=$r_u->{$_}} (qw'inGame away');
  if($gameDuration) {
    $self->{onAdditionalInGameTime}($r_connInfo,$login,$r_userInfo,$gameDuration)
        if(defined $self->{onAdditionalInGameTime});
    if(defined $self->{onAdditionalInGameTimeAsync}) {
      my $statusAlreadyBroadcasted;
      $self->{onAdditionalInGameTimeAsync}(
        sub {
          return if($hdl->destroyed() || ! shift);
          $r_userInfo->{marshalledStatus}=marshallClientStatus($r_userInfo->{status});
          my @inducedTraffic=broadcast($self,'CLIENTSTATUS',$login,$r_userInfo->{marshalledStatus});
          $statusAlreadyBroadcasted=1;
          closeClientConnection($self,$hdl,'induced traffic flood')
              if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
        },
        $r_connInfo,$login,$r_userInfo,$gameDuration,
      );
      return if($statusAlreadyBroadcasted);
    }
  }
  $r_userInfo->{marshalledStatus}=marshallClientStatus($r_userInfo->{status});
  return broadcast($self,'CLIENTSTATUS',$login,$r_userInfo->{marshalledStatus});
}

sub hChannels {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my @channelCmds=map {['CHANNEL',$_,scalar(keys %{$self->{channels}{$_}}),exists $self->{channelTopics}{$_} ? $self->{channelTopics}{$_}{topic} : ()]} (keys %{$self->{channels}});
  push(@channelCmds,['ENDOFCHANNELS']);
  return sendClientMulti($self,$hdl,\@channelCmds,$cmdId);
}

sub hJoin {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $chan=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid JOIN parameter') unless($chan =~ REGEX_CHANNEL);
  return if(exists $r_userInfo->{channels}{$chan});
  return sendClient($self,$hdl,['JOINFAILED',$chan,'invalid channel name'],$cmdId) if(substr($chan,0,2) eq '__');
  if(defined $self->{onChannelJoin}) {
    my $denyMsg=$self->{onChannelJoin}($r_connInfo,$login,$r_userInfo,$chan);
    return sendClient($self,$hdl,['JOINFAILED',$chan,$denyMsg],$cmdId) if(defined $denyMsg);
  }
  my @inducedTraffic=sendClient($self,$hdl,['JOIN',$chan],$cmdId);
  addInducedTraffic(\@inducedTraffic,broadcastChannel($self,$chan,'JOINED',$chan,$login));
  $r_userInfo->{channels}{$chan}=1;
  $self->{channels}{$chan}{$login}=1;
  my @joinCmds;
  my ($topic,$topicAuthor) = exists $self->{channelTopics}{$chan} ? @{$self->{channelTopics}{$chan}}{qw'topic author'} : ('','<null>');
  if($r_userInfo->{isLegacyClient}) {
    @joinCmds=(['CHANNELTOPIC',$chan,$topicAuthor,$self->{startTime}*1000,$topic]) unless($topic eq '');
  }else{
    @joinCmds=(['JOINED',$chan,$login],['CHANNELTOPIC',$chan,$topicAuthor,$topic]);
  }
  push(@joinCmds,['CLIENTS',$chan,join(' ',keys %{$self->{channelBots}{$chan}},keys %{$self->{channels}{$chan}})]);
  addInducedTraffic(\@inducedTraffic,sendClientMulti($self,$hdl,\@joinCmds));
  return @inducedTraffic;
}

sub hLeave {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $chan=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid LEAVE parameter') unless($chan =~ REGEX_CHANNEL);
  return removeUserFromChannel($self,$login,$chan);
}

# $kickAuthor must be defined if and only if the user didn't request to leave the channel (to trigger FORCELEAVECHANNEL for legacy clients)
# $kickAuthor can be set to "" to avoid the automatic "Kicked by ..." prefix
sub removeUserFromChannel {
  my ($self,$removedUser,$chan,$reason,$kickAuthor)=@_;
  my $r_userInfo=$self->{users}{$removedUser};
  return unless(defined $r_userInfo && exists $r_userInfo->{channels}{$chan});
  my @inducedTraffic;
  my @leftCmd=('LEFT',$chan,$removedUser);
  if($r_userInfo->{isLegacyClient}) {
    if(defined $kickAuthor) {
      my @forceLeaveCmd=('FORCELEAVECHANNEL',$chan);
      if($kickAuthor eq '') {
        push(@forceLeaveCmd,'*server*');
        if(defined $reason) {
          push(@forceLeaveCmd,$reason);
          push(@leftCmd,$reason);
        }
      }else{
        push(@forceLeaveCmd,$kickAuthor);
        push(@leftCmd,'Kicked by '.$kickAuthor);
        if(defined $reason) {
          push(@forceLeaveCmd,$reason);
          $leftCmd[-1].=': '.$reason;
        }
      }
      @inducedTraffic=sendUser($self,$removedUser,\@forceLeaveCmd);
    }elsif(defined $reason) {
      push(@leftCmd,$reason);
    }
    delete $self->{channels}{$chan}{$removedUser};
    addInducedTraffic(\@inducedTraffic,broadcastChannel($self,$chan,@leftCmd));
  }else{
    if(defined $kickAuthor && $kickAuthor ne '') {
      push(@leftCmd,'Kicked by '.$kickAuthor.(defined $reason ? ': '.$reason : ''));
    }elsif(defined $reason) {
      push(@leftCmd,$reason);
    }
    @inducedTraffic=broadcastChannel($self,$chan,@leftCmd);
    delete $self->{channels}{$chan}{$removedUser};
  }
  delete $self->{channels}{$chan} unless(%{$self->{channels}{$chan}});
  delete $r_userInfo->{channels}{$chan};
  return @inducedTraffic;
}

sub hSay {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my ($cmd,$chan,$msg)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error',"invalid $cmd parameter")
      unless($chan =~ REGEX_CHANNEL
             && length($msg) <= $self->{maxChatMsgLength});
  return hSayBattle($self,$hdl,$r_connInfo,$login,$r_userInfo,[$cmd eq 'SAY' ? 'SAYBATTLE' : 'SAYBATTLEEX',$msg],$cmdId)
      if($chan =~ /^__battle__(\d+)$/ && defined $r_userInfo->{battle} && $1 == $r_userInfo->{battle});
  return sendClient($self,$hdl,['SERVERMSG',"Cannot send message to channel \"$chan\": not in channel!"],$cmdId)
      unless(exists $r_userInfo->{channels}{$chan});
  my ($saidCmd,$isExMsg);
  if($cmd eq 'SAY') {
    ($saidCmd,$isExMsg)=('SAID',0);
  }else{
    ($saidCmd,$isExMsg)=('SAIDEX',1);
  }
  if(defined $self->{onChannelMsg}) {
    my $denyMsg=$self->{onChannelMsg}($r_connInfo,$login,$r_userInfo,$chan,\$msg,$isExMsg);
    if(defined $denyMsg) {
      return if($denyMsg eq '');
      return sendClient($self,$hdl,['SERVERMSG',"Failed to send message to channel \"$chan\": $denyMsg"],$cmdId);
    }
  }
  my @inducedTraffic=broadcastChannel($self,$chan,$saidCmd,$chan,$login,$msg);
  broadcastChannelMsgToSrvBots($self,$r_connInfo,$login,$r_userInfo,$chan,$msg,$isExMsg);
  return @inducedTraffic;
}

sub hSayPrivate {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my ($cmd,$recipient,$msg)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error',"invalid $cmd parameter")
      unless($recipient =~ REGEX_USERNAME
             && length($msg) <= $self->{maxChatMsgLength});
  my $isExMsg = $cmd eq 'SAYPRIVATEEX';
  if(exists $self->{users}{$recipient}) {
    my $r_recipientUserInfo=$self->{users}{$recipient};
    if(defined $self->{onPrivateMsg}) {
      my $denyMsg=$self->{onPrivateMsg}($r_connInfo,$login,$r_userInfo,$recipient,$r_recipientUserInfo,\$msg,$isExMsg,0);
      if(defined $denyMsg) {
        return if($denyMsg eq '');
        return sendClient($self,$hdl,['SERVERMSG',"Failed to send private message to $recipient: $denyMsg"],$cmdId);
      }
    }
    my @inducedTraffic=sendClient($self,$hdl,$r_cmd,$cmdId);
    my $accountId=$r_userInfo->{accountId};
    addInducedTraffic(\@inducedTraffic,sendUser($self,$recipient,[$isExMsg ? 'SAIDPRIVATEEX' : 'SAIDPRIVATE',$login,$msg]))
        unless($accountId && exists $r_recipientUserInfo->{ignoredAccounts}{$accountId});
    return @inducedTraffic;
  }elsif(exists $self->{serverBots}{$recipient}) {
    my @inducedTraffic=sendClient($self,$hdl,$r_cmd,$cmdId);
    sendPrivateMsgToSrvBot($self,$r_connInfo,$login,$r_userInfo,$recipient,$msg,$isExMsg);
    return @inducedTraffic;
  }else{
    $self->{debug} && $self->{logger}("\"$login\" tried to send private message to offline client \"$recipient\"",5);
    return;
  }
}

sub hOpenBattle {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$type,$natType,$password,$port,$maxPlayers,$gameHash,$rankLimit,$mapHash,$engineName,$engineVersion,$mapName,$title,$gameName)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid OPENBATTLE parameter') unless(
    $type =~ REGEX_BOOL
    && $natType =~ REGEX_ENUM2
    && length($password) < 50
    && $port =~ REGEX_PORT
    && $maxPlayers =~ REGEX_MAXPLAYERS
    && $gameHash =~ REGEX_INT32 && $gameHash >= INT32_MIN && $gameHash <= INT32_MAX
    && $rankLimit =~ REGEX_RANK
    && $mapHash =~ REGEX_INT32 && $mapHash >= INT32_MIN && $mapHash <= INT32_MAX
    && length($engineName) && length($engineName) < 100
    && length($engineVersion) && length($engineVersion) < 100
    && length($mapName) && length($mapName) < 100
    && length($title) && length($title) < 100
    && length($gameName) && length($gameName) < 100);
  return sendClient($self,$hdl,['OPENBATTLEFAILED','already in a battle'],$cmdId) if(defined $r_userInfo->{battle});
  $password='' if($password eq '*');
  my $bId=$self->{nextBattleId}++;
  $r_userInfo->{battle}=$bId;
  map {$_+=0} ($gameHash,$mapHash);
  $self->{battles}{$bId}={
    type => $type,
    natType => $natType,
    founder => $login,
    password => $password,
    ipAddr => $r_connInfo->{host},
    ipAddrType => $r_connInfo->{ipAddrType},
    lanIpAddr => $r_userInfo->{lanIpAddr},
    port => $port,
    maxPlayers => $maxPlayers,
    gameHash => $gameHash,
    rankLimit => $rankLimit,
    mapHash => $mapHash,
    engineName => $engineName,
    engineVersion => $engineVersion,
    mapName => $mapName,
    title => $title,
    gameName => $gameName,
    nbSpec => 0,
    locked => 0,
    users => {
      $login => {
        battleStatus => {
          side => 0,
          sync => 0,
          bonus => 0,
          mode => 0,
          team => 0,
          id => 0,
          ready => 0,
        },
        marshalledBattleStatus => 0,
        color => {
          red => 0,
          green => 0,
          blue => 0,
        },
        marshalledColor => 0,
      },
    },
    bots => {},
    disabledUnits => {},
    startRects => {},
    scriptTags => {},
  };
  my $r_funcGetBattleAddrForUser =
      $r_connInfo->{ipAddrType} == IP_ADDR_LOOPBACK ? \&getLoopbackBattleAddrForUser :
      $r_connInfo->{ipAddrType} == IP_ADDR_LAN ? \&getLanBattleAddrForUser :
      \&getWanBattleAddrForUser;
  my $hostLanIpAddr = $r_userInfo->{lanIpAddr} eq '*' ? undef : $r_userInfo->{lanIpAddr};
  my $selfWanIpAddr = (defined $self->{wanAddress} && $self->{wanAddress} ne '') ? $self->{wanAddress} : undef;
  my $isPassworded = $password eq '' ? 0 : 1;
  my @inducedTraffic;
  map {
    addInducedTraffic(
      \@inducedTraffic,
      sendUser($self,$_,['BATTLEOPENED',$bId,$type,$natType,$login,
                         $r_funcGetBattleAddrForUser->($self->{connections}{$self->{users}{$_}{connIdx}},$r_connInfo->{host},$hostLanIpAddr,$selfWanIpAddr),
                         $port,$maxPlayers,$isPassworded,$rankLimit,$mapHash,$engineName,$engineVersion,$mapName,$title,$gameName,
                         $self->{users}{$_}{compFlags}{u} ? '__battle__'.$bId : ()]))
  } (keys %{$self->{users}});
  addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['OPENBATTLE',$bId],$cmdId));
  my @openBattleResCmds;
  push(@openBattleResCmds,['JOINBATTLE',$bId,$gameHash,$r_userInfo->{compFlags}{u} ? '__battle__'.$bId : ()]) unless($r_userInfo->{isLegacyClient});
  push(@openBattleResCmds,['REQUESTBATTLESTATUS']);
  addInducedTraffic(\@inducedTraffic,sendClientMulti($self,$hdl,\@openBattleResCmds));
  return @inducedTraffic;
}

sub hJoinBattle {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$bId,$password,$scriptPassword)=@{$r_cmd};
  $password='' unless(defined $password && $password ne '*');
  $scriptPassword//='';
  return closeClientConnection($self,$hdl,'protocol error','invalid JOINBATTLE parameter') unless(
    $bId =~ REGEX_BATTLEID
    && length($password) < 50
    && $scriptPassword =~ REGEX_SCRIPTPASSWD);
  return sendClient($self,$hdl,['JOINBATTLEFAILED','invalid battle ID'],$cmdId) unless(exists $self->{battles}{$bId});
  return sendClient($self,$hdl,['JOINBATTLEFAILED','battle is locked'],$cmdId) if($self->{battles}{$bId}{locked});
  if($self->{battles}{$bId}{password} ne '') {
    return sendClient($self,$hdl,['JOINBATTLEFAILED','battle is password protected'],$cmdId) if($password eq '');
    return sendClient($self,$hdl,['JOINBATTLEFAILED','invalid password'],$cmdId) if($password ne $self->{battles}{$bId}{password});
  }
  return sendClient($self,$hdl,['JOINBATTLEFAILED','already in a battle'],$cmdId) if(defined $r_userInfo->{battle});
  my $battleFounder=$self->{battles}{$bId}{founder};
  if(defined $self->{onBattleJoin}) {
    my $denyMsg=$self->{onBattleJoin}($r_connInfo,$login,$r_userInfo,$battleFounder,$self->{users}{$battleFounder},$bId);
    return sendClient($self,$hdl,['JOINBATTLEFAILED',$denyMsg],$cmdId) if(defined $denyMsg);
  }
  $r_userInfo->{pendingBattleJoin}=[$bId,$scriptPassword];
  return sendUser($self,$battleFounder,['JOINBATTLEREQUEST',$login,$r_connInfo->{host}]);
}

sub hJoinBattleAccept {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $joiningUser=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid JOINBATTLEACCEPT parameter')
      unless($joiningUser =~ REGEX_USERNAME);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login && exists $self->{users}{$joiningUser} && ! defined $self->{users}{$joiningUser}{battle});
  my $r_joiningUserInfo=$self->{users}{$joiningUser};
  my $r_pendingJoinData=$r_joiningUserInfo->{pendingBattleJoin};
  return unless(defined $r_pendingJoinData && $r_pendingJoinData->[0] eq $bId);
  my $joiningUserConnIdx=$r_joiningUserInfo->{connIdx};
  my @inducedTraffic=sendClientMultiByIdx($self,$joiningUserConnIdx,[
                                            ['JOINBATTLE',$bId,$r_b->{gameHash},$r_joiningUserInfo->{compFlags}{u} ? '__battle__'.$bId : ()],
                                            ['JOINEDBATTLE',$bId,$joiningUser,$r_pendingJoinData->[1]]
                                          ]);
  addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['JOINEDBATTLE',$bId,$joiningUser,$r_pendingJoinData->[1]],$cmdId));
  map {addInducedTraffic(\@inducedTraffic,sendUser($self,$_,['JOINEDBATTLE',$bId,$joiningUser])) unless($_ eq $login || $_ eq $joiningUser)} (keys %{$self->{users}});
  delete $r_joiningUserInfo->{pendingBattleJoin};
  $r_joiningUserInfo->{battle}=$bId;
  $r_b->{users}{$joiningUser} = {
    battleStatus => {
      side => 0,
      sync => 0,
      bonus => 0,
      mode => 0,
      team => 0,
      id => 0,
      ready => 0,
    },
    marshalledBattleStatus => 0,
    color => {
      red => 0,
      green => 0,
      blue => 0,
    },
    marshalledColor => 0,
  };
  my @joinResCmds=(['SETSCRIPTTAGS',map {$_.'='.$r_b->{scriptTags}{$_}} (keys %{$r_b->{scriptTags}})]);
  push(@joinResCmds,['DISABLEDUNITS',keys %{$r_b->{disabledUnits}}]) if(%{$r_b->{disabledUnits}});
  map {
    push(@joinResCmds,['CLIENTBATTLESTATUS',$_,$r_b->{users}{$_}{marshalledBattleStatus},$r_b->{users}{$_}{marshalledColor}])
        if($r_b->{users}{$_}{marshalledBattleStatus} || $r_b->{users}{$_}{marshalledColor})
  } (keys %{$r_b->{users}});
  map {push(@joinResCmds,['ADDBOT',$bId,$_,$r_b->{bots}{$_}{owner},$r_b->{bots}{$_}{marshalledBattleStatus},$r_b->{bots}{$_}{marshalledColor},$r_b->{bots}{$_}{aiDll}])} (keys %{$r_b->{bots}});
  map {push(@joinResCmds,['ADDSTARTRECT',$_,@{$r_b->{startRects}{$_}}{qw'left top right bottom'}])} (sort {$a <=> $b} keys %{$r_b->{startRects}});
  push(@joinResCmds,['REQUESTBATTLESTATUS']);
  addInducedTraffic(\@inducedTraffic,sendClientMultiByIdx($self,$joiningUserConnIdx,\@joinResCmds));
  closeClientConnection($self,$self->{connections}{$joiningUserConnIdx}{hdl},'induced traffic flood')
      if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_joiningUserInfo,@inducedTraffic));
  return;
}

sub hJoinBattleDeny {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$joiningUser,$reason)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid JOINBATTLEDENY parameter')
      unless($joiningUser =~ REGEX_USERNAME);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login);
  my $r_joiningUserInfo=$self->{users}{$joiningUser};
  return unless(defined $r_joiningUserInfo && ! defined $r_joiningUserInfo->{battle});
  my $r_pendingJoinData=$r_joiningUserInfo->{pendingBattleJoin};
  return unless(defined $r_pendingJoinData && $r_pendingJoinData->[0] eq $bId);
  delete $r_joiningUserInfo->{pendingBattleJoin};
  my $joiningUserConnIdx=$r_joiningUserInfo->{connIdx};
  $reason='access denied by host'.(defined $reason ? ' - '.$reason : '');
  my @inducedTraffic=sendClientByIdx($self,$joiningUserConnIdx,['JOINBATTLEFAILED',$reason]);
  closeClientConnection($self,$self->{connections}{$joiningUserConnIdx}{hdl},'induced traffic flood')
      if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_joiningUserInfo,@inducedTraffic));
  return;
}

sub hLeaveBattle {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  return removeUserFromBattle($self,$login,$bId);
}

sub hKickFromBattle {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $kickedUser=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid KICKFROMBATTLE parameter')
      unless($kickedUser =~ REGEX_USERNAME);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login && exists $r_b->{users}{$kickedUser});
  my @inducedTraffic=sendUser($self,$kickedUser,['FORCEQUITBATTLE']);
  addInducedTraffic(\@inducedTraffic,removeUserFromBattle($self,$kickedUser,$bId));
  return @inducedTraffic;
}

sub removeUserFromBattle {
  my ($self,$user,$bId)=@_;
  my $r_b=$self->{battles}{$bId};
  if($user eq $r_b->{founder}) {
    map {undef $self->{users}{$_}{battle}} (keys %{$r_b->{users}});
    delete $self->{battles}{$bId};
    return broadcast($self,'BATTLECLOSED',$bId);
  }else{
    undef $self->{users}{$user}{battle};
    delete $r_b->{users}{$user};
    my @inducedTraffic;
    map {delete $r_b->{bots}{$_}; addInducedTraffic(\@inducedTraffic,broadcastBattle($self,$bId,'REMOVEBOT',$bId,$_))} (grep {$r_b->{bots}{$_}{owner} eq $user} (keys %{$r_b->{bots}}));
    addInducedTraffic(\@inducedTraffic,broadcast($self,'LEFTBATTLE',$bId,$user));
    return @inducedTraffic;
  }
}

sub hMyBattleStatus {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$marshalledBattleStatus,$marshalledColor)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid MYBATTLESTATUS parameter')
      unless(all {$_ =~ REGEX_INT32 && $_ >= INT32_MIN && $_ <= INT32_MAX} ($marshalledBattleStatus,$marshalledColor));
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  my $r_bu=$r_b->{users}{$login};
  my $r_bs=unmarshallBattleStatus($marshalledBattleStatus);
  $r_bs->{mode}=0
      if($r_bs->{mode}
         && ! $r_bu->{battleStatus}{mode}
         && scalar(grep {$r_b->{users}{$_}{battleStatus}{mode}} (keys %{$r_b->{users}})) >= $r_b->{maxPlayers});
  my $commandIsEffective;
  if(any {$_ ne 'bonus' && $r_bs->{$_} != $r_bu->{battleStatus}{$_}} (keys %{$r_bs})) {
    $commandIsEffective=1;
    $r_bs->{bonus}=$r_bu->{battleStatus}{bonus};
    $r_bu->{battleStatus}=$r_bs;
    $r_bu->{marshalledBattleStatus}=marshallBattleStatus($r_bs); # always remarshall to enforce unused bits = 0
  }
  my $r_c=unmarshallColor($marshalledColor);
  if(any {$r_c->{$_} != $r_bu->{color}{$_}} (keys %{$r_c})) {
    $commandIsEffective=1;
    $r_bu->{color}=$r_c;
    $r_bu->{marshalledColor}=marshallColor($r_c); # always remarshall to enforce unused bits = 0
  }
  return broadcastBattle($self,$bId,'CLIENTBATTLESTATUS',$login,$r_bu->{marshalledBattleStatus},$r_bu->{marshalledColor}) if($commandIsEffective);
  return;
}

sub hAddBot {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$botName,$marshalledBattleStatus,$marshalledColor,$aiDll)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid ADDBOT parameter')
      unless($botName =~ REGEX_USERNAME
             && (all {$_ =~ REGEX_INT32 && $_ >= INT32_MIN && $_ <= INT32_MAX} ($marshalledBattleStatus,$marshalledColor))
             && length($aiDll) && length($aiDll) < 50);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return if(exists $r_b->{bots}{$botName});
  my $r_bs=unmarshallBattleStatus($marshalledBattleStatus);
  my $r_c=unmarshallColor($marshalledColor);
  $r_b->{bots}{$botName}={
    owner => $login,
    battleStatus => $r_bs,
    marshalledBattleStatus => marshallBattleStatus($r_bs),
    color => $r_c,
    marshalledColor => marshallColor($r_c),
    aiDll => $aiDll,
  };
  return broadcastBattle($self,$bId,'ADDBOT',$bId,$botName,$login,$r_b->{bots}{$botName}{marshalledBattleStatus},$r_b->{bots}{$botName}{marshalledColor},$aiDll);
}

sub hRemoveBot {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $botName=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid REMOVEBOT parameter')
      unless($botName =~ REGEX_USERNAME);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless(exists $r_b->{bots}{$botName} && $r_b->{bots}{$botName}{owner} eq $login || $r_b->{founder} eq $login);
  delete $r_b->{bots}{$botName};
  return broadcastBattle($self,$bId,'REMOVEBOT',$bId,$botName);
}

sub hUpdateBot {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$botName,$marshalledBattleStatus,$marshalledColor)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid UPDATEBOT parameter')
      unless($botName =~ REGEX_USERNAME
             && (all {$_ =~ REGEX_INT32 && $_ >= INT32_MIN && $_ <= INT32_MAX} ($marshalledBattleStatus,$marshalledColor)));
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_bb=$self->{battles}{$bId}{bots}{$botName};
  return unless(defined $r_bb && $r_bb->{owner} eq $login || $self->{battles}{$bId}{founder} eq $login);
  my $r_bs=unmarshallBattleStatus($marshalledBattleStatus);
  my $commandIsEffective;
  if(any {$r_bs->{$_} != $r_bb->{battleStatus}{$_}} (keys %{$r_bs})) {
    $commandIsEffective=1;
    $r_bb->{battleStatus}=$r_bs;
    $r_bb->{marshalledBattleStatus}=marshallBattleStatus($r_bs); # always remarshall to enforce unused bits = 0
  }
  my $r_c=unmarshallColor($marshalledColor);
  if(any {$r_c->{$_} != $r_bb->{color}{$_}} (keys %{$r_c})) {
    $commandIsEffective=1;
    $r_bb->{color}=$r_c;
    $r_bb->{marshalledColor}=marshallColor($r_c); # always remarshall to enforce unused bits = 0
  }
  return broadcastBattle($self,$bId,'UPDATEBOT',$bId,$botName,$r_bb->{marshalledBattleStatus},$r_bb->{marshalledColor}) if($commandIsEffective);
  return;
}

sub hForceSpectatorMode {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $forcedUser=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid FORCESPECTATORMODE parameter')
      unless($forcedUser =~ REGEX_USERNAME);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  my $r_bu=$r_b->{users}{$forcedUser};
  return unless($r_b->{founder} eq $login && defined $r_bu && $r_bu->{battleStatus}{mode});
  $r_bu->{battleStatus}{mode}=0;
  $r_bu->{marshalledBattleStatus}=marshallBattleStatus($r_bu->{battleStatus});
  return broadcastBattle($self,$bId,'CLIENTBATTLESTATUS',$forcedUser,$r_bu->{marshalledBattleStatus},$r_bu->{marshalledColor});
}

sub hForceTeamNo {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$forcedUser,$teamNb)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid FORCETEAMNO parameter')
      unless($forcedUser =~ REGEX_USERNAME
             && $teamNb =~ REGEX_TEAMID);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  my $r_bu=$r_b->{users}{$forcedUser};
  return unless($r_b->{founder} eq $login && defined $r_bu && $r_bu->{battleStatus}{id} != $teamNb);
  $r_bu->{battleStatus}{id}=$teamNb;
  $r_bu->{marshalledBattleStatus}=marshallBattleStatus($r_bu->{battleStatus});
  return broadcastBattle($self,$bId,'CLIENTBATTLESTATUS',$forcedUser,$r_bu->{marshalledBattleStatus},$r_bu->{marshalledColor});
}

sub hForceAllyNo {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$forcedUser,$teamNb)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid FORCEALLYNO parameter')
      unless($forcedUser =~ REGEX_USERNAME
             && $teamNb =~ REGEX_TEAMID);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  my $r_bu=$r_b->{users}{$forcedUser};
  return unless($r_b->{founder} eq $login && defined $r_bu && $r_bu->{battleStatus}{team} != $teamNb);
  $r_bu->{battleStatus}{team}=$teamNb;
  $r_bu->{marshalledBattleStatus}=marshallBattleStatus($r_bu->{battleStatus});
  return broadcastBattle($self,$bId,'CLIENTBATTLESTATUS',$forcedUser,$r_bu->{marshalledBattleStatus},$r_bu->{marshalledColor});
}

sub hHandicap {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$forcedUser,$bonus)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid HANDICAP parameter')
      unless($forcedUser =~ REGEX_USERNAME
             && $bonus =~ REGEX_TEAMID);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  my $r_bu=$r_b->{users}{$forcedUser};
  return unless($r_b->{founder} eq $login && defined $r_bu && $r_bu->{battleStatus}{bonus} != $bonus);
  $r_bu->{battleStatus}{bonus}=$bonus;
  $r_bu->{marshalledBattleStatus}=marshallBattleStatus($r_bu->{battleStatus});
  return broadcastBattle($self,$bId,'CLIENTBATTLESTATUS',$forcedUser,$r_bu->{marshalledBattleStatus},$r_bu->{marshalledColor});
}

sub hForceTeamColor {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$forcedUser,$marshalledColor)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid FORCETEAMCOLOR parameter')
      unless($forcedUser =~ REGEX_USERNAME
             && $marshalledColor =~ REGEX_INT32 && $marshalledColor >= INT32_MIN && $marshalledColor <= INT32_MAX);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  my $r_bu=$r_b->{users}{$forcedUser};
  return unless($r_b->{founder} eq $login && defined $r_bu);
  my $r_c=unmarshallColor($marshalledColor);
  if(any {$r_c->{$_} != $r_bu->{color}{$_}} (keys %{$r_c})) {
    $r_bu->{color}=$r_c;
    $r_bu->{marshalledColor}=marshallColor($r_c); # always remarshall to enforce unused bits = 0
    return broadcastBattle($self,$bId,'CLIENTBATTLESTATUS',$forcedUser,$r_bu->{marshalledBattleStatus},$r_bu->{marshalledColor});
  }
  return;
}

sub hSetScriptTags {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@scriptTagDefs)=@{$r_cmd};
  pop(@scriptTagDefs) if(@scriptTagDefs && $scriptTagDefs[-1] eq ''); # springlobby sometimes puts an empty string at the end...
  my %scriptTags;
  foreach my $scriptTagDef (@scriptTagDefs) {
    if($scriptTagDef =~ REGEX_SCRIPTTAGDEF) {
      $scriptTags{lc($1)}=$2;
    }else{
      return closeClientConnection($self,$hdl,'protocol error','invalid SETSCRIPTTAGS parameter');
    }
  }
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId && $self->{battles}{$bId}{founder} eq $login);
  my $r_battleScriptTags=$self->{battles}{$bId}{scriptTags};
  my @changedScriptTags;
  my $nbNewScriptTags;
  foreach my $scriptTag (keys %scriptTags) {
    if(exists $r_battleScriptTags->{$scriptTag}) {
      push(@changedScriptTags,$scriptTag) if($r_battleScriptTags->{$scriptTag} ne $scriptTags{$scriptTag});
    }else{
      push(@changedScriptTags,$scriptTag);
      $nbNewScriptTags++;
    }
  }
  return unless(@changedScriptTags);
  return closeClientConnection($self,$hdl,'too many script tags in battle')
      if($nbNewScriptTags && keys(%{$r_battleScriptTags}) + $nbNewScriptTags > $self->{maxBattleScriptTags});
  map {$r_battleScriptTags->{$_}=$scriptTags{$_}} @changedScriptTags;
  return broadcastBattle($self,$bId,'SETSCRIPTTAGS',map {$_.'='.$scriptTags{$_}} @changedScriptTags);
}

sub hRemoveSCriptTags {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@scriptTags)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid REMOVESCRIPTTAGS parameter')
      unless(all {$_ =~ REGEX_SCRIPTTAG} @scriptTags);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId && $self->{battles}{$bId}{founder} eq $login);
  my @scriptTagsToDelete=grep {exists $self->{battles}{$bId}{scriptTags}{$_}} @scriptTags;
  return unless(@scriptTagsToDelete);
  delete @{$self->{battles}{$bId}{scriptTags}}{@scriptTagsToDelete};
  return broadcastBattle($self,$bId,'REMOVESCRIPTTAGS',@scriptTagsToDelete);
}

sub hDisableUnits {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@units)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid DISABLEUNITS parameter')
      unless(all {$_ =~ REGEX_UNIT} @units);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login);
  my @unitsToDisable=grep {! exists $r_b->{disabledUnits}{$_}} @units;
  return unless(@unitsToDisable);
  map {$r_b->{disabledUnits}{$_}=1} @unitsToDisable;
  return broadcastBattle($self,$bId,'DISABLEUNITS',@unitsToDisable);
}

sub hEnableUnits {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@units)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid ENABLEUNITS parameter')
      unless(all {$_ =~ REGEX_UNIT} @units);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login);
  my @unitsToEnable=grep {exists $r_b->{disabledUnits}{$_}} @units;
  return unless(@unitsToEnable);
  map {delete $r_b->{disabledUnits}{$_}} @unitsToEnable;
  return broadcastBattle($self,$bId,'ENABLEUNITS',@unitsToEnable);
}

sub hEnableAllUnits {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login && %{$r_b->{disabledUnits}});
  $r_b->{disabledUnits}={};
  return broadcastBattle($self,$bId,'ENABLEALLUNITS');
}

sub hUpdateBattleInfo {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$nbSpec,$locked,$mapHash,$mapName)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid UPDATEBATTLEINFO parameter')
      unless($nbSpec =~ REGEX_NBSPEC
             && $locked =~ REGEX_BOOL
             && $mapHash =~ REGEX_INT32 && $mapHash >= INT32_MIN && $mapHash <= INT32_MAX
             && length($mapName) && length($mapName) < 100);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login);
  return if($r_b->{nbSpec} == $nbSpec
            && $r_b->{locked} == $locked
            && $r_b->{mapHash} == $mapHash
            && $r_b->{mapName} eq $mapName);
  $mapHash+=0;
  $r_b->{nbSpec}=$nbSpec;
  $r_b->{locked}=$locked;
  $r_b->{mapHash}=$mapHash;
  $r_b->{mapName}=$mapName;
  return broadcast($self,'UPDATEBATTLEINFO',$bId,$nbSpec,$locked,$mapHash,$mapName);
}

sub hAddStartRect {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$team,$left,$top,$right,$bottom)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid ADDSTARTRECT parameter')
      unless($team =~ REGEX_TEAMID
             && (all {$_ =~ REGEX_STARTRECT} ($left,$top,$right,$bottom)));
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login);
  return if(exists $r_b->{startRects}{$team}
            && $r_b->{startRects}{$team}{left} == $left
            && $r_b->{startRects}{$team}{top} == $top
            && $r_b->{startRects}{$team}{right} == $right
            && $r_b->{startRects}{$team}{bottom} == $bottom);
  $r_b->{startRects}{$team}={left => $left, top => $top, right => $right, bottom => $bottom};
  return broadcastBattle($self,$bId,'ADDSTARTRECT',$team,$left,$top,$right,$bottom);
}

sub hRemoveStartRect {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $team=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error','invalid REMOVESTARTRECT parameter')
      unless($team =~ REGEX_TEAMID);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login && exists $r_b->{startRects}{$team});
  delete $r_b->{startRects}{$team};
  return broadcastBattle($self,$bId,'REMOVESTARTRECT',$team);
}

sub hSayBattle {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my ($cmd,$msg)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error',"invalid $cmd parameter")
      unless(length($msg) <= $self->{maxChatMsgLength});
  my $bId=$r_userInfo->{battle};
  return sendClient($self,$hdl,['SERVERMSG','Cannot send message in battle lobby: not in a battle!'],$cmdId)
      unless(defined $bId);
  my $battleFounder=$self->{battles}{$bId}{founder};
  my $isExMsg = $cmd eq 'SAYBATTLEEX';
  if(defined $self->{onBattleMsg}) {
    my $denyMsg=$self->{onBattleMsg}($r_connInfo,$login,$r_userInfo,$battleFounder,$self->{users}{$battleFounder},$bId,\$msg,$isExMsg);
    if(defined $denyMsg) {
      return sendClient($self,$hdl,['SERVERMSG',"Failed to send message in battle lobby: $denyMsg"],$cmdId)
          unless($denyMsg eq '');
      return;
    }
  }
  return broadcastBattleUFlag($self,$bId,[$isExMsg ? 'SAIDEX' : 'SAID','__battle__'.$bId,$login,$msg],[$isExMsg ? 'SAIDBATTLEEX' : 'SAIDBATTLE',$login,$msg]);
}

sub hSayBattlePrivate {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my ($cmd,$recipientsStr,$msg)=@{$r_cmd};
  my @recipients=split(',',$recipientsStr);
  return closeClientConnection($self,$hdl,'protocol error',"invalid $cmd parameter")
      unless((all {$_ =~ REGEX_USERNAME} @recipients)
             && length($msg) <= $self->{maxChatMsgLength});
  my $bId=$r_userInfo->{battle};
  return sendClient($self,$hdl,['SERVERMSG',"Cannot send private message to $recipientsStr in battle lobby: not in a battle!"],$cmdId)
      unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login);
  @recipients=grep {exists $r_b->{users}{$_}} @recipients;
  return unless(@recipients);
  my $isExMsg = $cmd eq 'SAYBATTLEPRIVATEEX';
  my @inducedTraffic;
  foreach my $recipient (@recipients) {
    if(defined $self->{onPrivateMsg}) {
      my $denyMsg=$self->{onPrivateMsg}($r_connInfo,$login,$r_userInfo,$recipient,$self->{users}{$recipient},\$msg,$isExMsg,1);
      if(defined $denyMsg) {
        addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['SERVERMSG',"Failed to send private message to $recipient in battle lobby: $denyMsg"],$cmdId))
            unless($denyMsg eq '');
        next;
      }
    }
    if($self->{users}{$recipient}{compFlags}{u}) {
      addInducedTraffic(\@inducedTraffic,sendUser($self,$recipient,[$isExMsg ? 'SAIDEX' : 'SAID','__battle__'.$bId,$login,$msg]));
    }else{
      addInducedTraffic(\@inducedTraffic,sendUser($self,$recipient,[$isExMsg ? 'SAIDBATTLEEX' : 'SAIDBATTLE',$login,$msg]));
    }
  }
  return @inducedTraffic;
}

sub hRing {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $recipient=$r_cmd->[1];
  return closeClientConnection($self,$hdl,'protocol error',"invalid RING parameter") unless($recipient =~ REGEX_USERNAME);
  my $bId=$r_userInfo->{battle};
  return unless(defined $bId);
  my $r_b=$self->{battles}{$bId};
  return unless($r_b->{founder} eq $login && exists $r_b->{users}{$recipient});
  my $accountId=$r_userInfo->{accountId};
  return if($accountId && exists $self->{users}{$recipient}{ignoredAccounts}{$accountId});
  return sendUser($self,$recipient,['RING',$login]);
}

sub hGetUserInfo {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $userName=$r_cmd->[1];
  if(defined $userName && $userName ne $login) {
    return sendClient($self,$hdl,['SERVERMSG','Your are not allowed to retrieve user information of other accounts'])
        unless($r_userInfo->{status}{access});
    return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid GETUSERINFO parameter'],$cmdId)
        unless($userName =~ REGEX_USERNAME);
    my $r_onlineUserInfo=$self->{users}{$userName};
    if(defined $r_onlineUserInfo) {
      return sendUserInfoAsServerMsg($self,$hdl,$userName,$r_onlineUserInfo,$cmdId,1);
    }elsif(exists $self->{accountManagementSvc}{GETUSERINFO}) {
      $self->{accountManagementSvc}{GETUSERINFO}(
        sub {
          return if($hdl->destroyed());
          my ($failedReason,$r_offlineUserInfo)=@_;
          if(defined $failedReason) {
            sendClient($self,$hdl,['SERVERMSG','Failed to retrieve user information for '.$userName.': '.$failedReason],$cmdId);
          }else{
            sendUserInfoAsServerMsg($self,$hdl,$userName,$r_offlineUserInfo,$cmdId,1);
          }
        },
        $r_connInfo,$login,$r_userInfo,$userName,
      );
      return;
    }else{
      return sendClient($self,$hdl,['SERVERMSG','Cannot retrieve user information of offline user, feature is not supported by this server'],$cmdId);
    }
  }else{
    return sendUserInfoAsServerMsg($self,$hdl,$login,$r_userInfo,$cmdId,$r_userInfo->{status}{access});
  }
}

sub sendUserInfoAsServerMsg {
  my ($self,$hdl,$userName,$r_userInfo,$cmdId,$fullAccess)=@_;
  my $userIsOnline;
  my @userInfoMsgs;
  if($fullAccess) {
    $userIsOnline=exists $r_userInfo->{connIdx};
    push(@userInfoMsgs,$userName.' is '.($userIsOnline ? 'online' : 'offline'));
    my $accountId=$r_userInfo->{accountId};
    push(@userInfoMsgs,'Account ID: '.$accountId) if($accountId);
  }
  push(@userInfoMsgs,'Registration date: '.timestampToGmTime($r_userInfo->{registrationTs})) if(defined $r_userInfo->{registrationTs});
  push(@userInfoMsgs,'Email address: '.$r_userInfo->{emailAddress}) if(defined $r_userInfo->{emailAddress});
  push(@userInfoMsgs,'Ingame time: '.secToTime($r_userInfo->{inGameTime})) if(defined $r_userInfo->{inGameTime});
  if($fullAccess) {
    push(@userInfoMsgs,'Last login: '.timestampToGmTime($r_userInfo->{lastLoginTs})) if(defined $r_userInfo->{lastLoginTs});
    push(@userInfoMsgs,'Lobby client: '.$r_userInfo->{lobbyClient}) if(defined $r_userInfo->{lobbyClient});
    push(@userInfoMsgs,'MAC address hash: '.$r_userInfo->{macAddressHash}) if(defined $r_userInfo->{macAddressHash});
    push(@userInfoMsgs,'System hash: '.$r_userInfo->{systemHash}) if(defined $r_userInfo->{systemHash});
    push(@userInfoMsgs,'Access level: '.$r_userInfo->{accessLevel}) if(defined $r_userInfo->{accessLevel});
    push(@userInfoMsgs,'Country: '.$r_userInfo->{country}) if(defined $r_userInfo->{country});
    if($userIsOnline) {
      my $r_connInfo=$self->{connections}{$r_userInfo->{connIdx}};
      push(@userInfoMsgs,'Connection time: '.secToTime(time-$r_connInfo->{connectTime}));
      push(@userInfoMsgs,'Lobby status: '.join(', ',map {$_.':'.$r_userInfo->{status}{$_}} (sort keys %{$r_userInfo->{status}})));
      push(@userInfoMsgs,'IP address: '.$r_connInfo->{host});
    }else{
      push(@userInfoMsgs,'Last IP address: '.$r_userInfo->{lastIpAddr}) if(defined $r_userInfo->{lastIpAddr});
    }
  }
  return sendClientMulti($self,$hdl,[map {['SERVERMSG',$_]} @userInfoMsgs],$cmdId);
}

sub timestampToGmTime {
  my @gmtime=gmtime(shift);
  $gmtime[4]++;
  @gmtime = map {sprintf('%02d',$_)} @gmtime;
  return ($gmtime[5]+1900).'-'.$gmtime[4].'-'.$gmtime[3].' '.$gmtime[2].':'.$gmtime[1].':'.$gmtime[0].' GMT';
}

sub hForceLeaveChannel {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$chan,$kickedUser,$reason)=@{$r_cmd};
  undef $reason if(defined $reason && $reason eq '');
  return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid FORCELEAVECHANNEL parameter'],$cmdId)
      unless($chan =~ REGEX_CHANNEL
             && $kickedUser =~ REGEX_USERNAME
             && (! defined $reason || length($reason) < 255));
  return removeUserFromChannel($self,$kickedUser,$chan,$reason,$login);
}

sub hKick {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$kickedUser,$reason)=@{$r_cmd};
  undef $reason if(defined $reason && $reason eq '');
  return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid KICK parameter'],$cmdId)
      unless($kickedUser =~ REGEX_USERNAME
             && (! defined $reason || length($reason) < 255));
  return sendClient($self,$hdl,['SERVERMSG','Cannot kick '.$kickedUser.', user not found online'],$cmdId)
      unless(exists $self->{users}{$kickedUser});
  my @inducedTraffic=kickUserFromServer($self,$kickedUser,$login,$reason);
  addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['SERVERMSG','Kicked '.$kickedUser.' from the server'],$cmdId));
  return @inducedTraffic;
}

sub kickUserFromServer {
  my ($self,$kickedUser,$login,$reason,$isBanned)=@_;
  my $kickedOrBanned=$isBanned?'banned':'kicked';
  my $r_kickedUserInfo=$self->{users}{$kickedUser};
  my $bId=$r_kickedUserInfo->{battle};
  my @inducedTraffic;
  @inducedTraffic=sendUser($self,$self->{battles}{$bId}{founder},['KICKFROMBATTLE',$bId,$kickedUser])
      if(defined $bId);
  addInducedTraffic(\@inducedTraffic,sendUser($self,$kickedUser,['SERVERMSGBOX','You were '.$kickedOrBanned.' from the server by '.$login.(defined $reason ? " ($reason)" : '')]));
  closeClientConnection($self,$self->{connections}{$r_kickedUserInfo->{connIdx}}{hdl},$kickedOrBanned.' from server by '.$login,$reason);
  return @inducedTraffic;
}

sub hSetBotMode {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$botName,$botMode)=@{$r_cmd};
  return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid SETBOTMODE parameter (botName)'],$cmdId)
      unless($botName =~ REGEX_USERNAME);
  my $lcBotMode=lc($botMode);
  if(any {$lcBotMode eq $_} (qw'0 false no disabled')) {
    $botMode=0;
  }elsif(any {$lcBotMode eq $_} (qw'1 true yes enabled')) {
    $botMode=1;
  }else{
    return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid SETBOTMODE parameter (botMode)'],$cmdId);
  }
  my $r_botInfo=$self->{users}{$botName};
  return sendClient($self,$hdl,['SERVERMSG','Failed to set bot mode for '.$botName.': bot mode is already set to '.$botMode],$cmdId)
      if(defined $r_botInfo && $r_botInfo->{status}{bot} == $botMode);
  if(exists $self->{accountManagementSvc}{SETBOTMODE}) {
    $self->{accountManagementSvc}{SETBOTMODE}(
      sub {
        my ($failedReason,$updatedAccountId)=@_;
        my @inducedTraffic;
        if(defined $failedReason) {
          return if($hdl->destroyed());
          @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to set bot mode for '.$botName.': '.$failedReason],$cmdId);
        }else{
          # updated client may have disconnected, reconnected and even renamed during async processing...
          my ($currentBotName,$r_currentBotInfo)=getOnlineClientData($self,$updatedAccountId,$botName);
          if(defined $r_currentBotInfo && $r_currentBotInfo->{status}{bot} != $botMode) {
            $r_currentBotInfo->{status}{bot}=$botMode;
            $r_currentBotInfo->{marshalledStatus}=marshallClientStatus($r_currentBotInfo->{status});
            @inducedTraffic=broadcast($self,'CLIENTSTATUS',$currentBotName,$r_currentBotInfo->{marshalledStatus});
          }
          return if($hdl->destroyed());
          addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['SERVERMSG','Bot mode for '.$botName.' successfully set to '.$botMode],$cmdId));
        }
        closeClientConnection($self,$hdl,'induced traffic flood')
            if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      },
      $r_connInfo,$login,$r_userInfo,$botName,$botMode,
    );
    return;
  }elsif(defined $r_botInfo) {
    $r_botInfo->{status}{bot}=$botMode;
    $r_botInfo->{marshalledStatus}=marshallClientStatus($r_botInfo->{status});
    my @inducedTraffic=broadcast($self,'CLIENTSTATUS',$botName,$r_botInfo->{marshalledStatus});
    addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['SERVERMSG','Bot mode for '.$botName.' successfully set to '.$botMode],$cmdId));
    return @inducedTraffic;
  }else{
    return sendClient($self,$hdl,['SERVERMSG','Cannot set bot mode of offline client, feature is not supported by this server'],$cmdId);
  }
}

sub hCreateBotAccount {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$botName,$ownerName)=@{$r_cmd};
  return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid CREATEBOTACCOUNT parameter'],$cmdId)
      unless($botName =~ REGEX_USERNAME && $ownerName =~ REGEX_USERNAME);
  return sendClient($self,$hdl,['SERVERMSG','Cannot create bot account, feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{CREATEBOTACCOUNT});
  my $lcBotName=lc($botName);
  my $denyReason = exists $self->{lcUsers}{$lcBotName} ? 'account already exists'
      : exists $self->{lcServerBots}{$lcBotName} ? 'name is reserved for internal use'
      : undef;
  return sendClient($self,$hdl,['SERVERMSG','Failed to create bot account '.$botName.': '.$denyReason],$cmdId)
      if(defined $denyReason);
  $self->{accountManagementSvc}{CREATEBOTACCOUNT}(
    sub {
      return if($hdl->destroyed());
      my $failedReason=shift;
      my @inducedTraffic;
      if(defined $failedReason) {
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to create bot account '.$botName.': '.$failedReason],$cmdId);
      }else{
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','A new bot account '.$botName.' has been created, with the same password as '.$ownerName],$cmdId);
      }
      closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
    },
    $r_connInfo,$login,$r_userInfo,$botName,$ownerName,
  );
  return;
}

sub hBan {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$userName,$duration,$reason)=@{$r_cmd};
  undef $reason if(defined $reason && $reason eq '');
  if(defined $duration) {
    $duration=0 if($duration eq '');
  }else{
    $duration=0;
  }
  return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid BAN parameter'],$cmdId)
      unless($userName =~ REGEX_USERNAME
             && $duration =~ REGEX_BANDURATION
             && (! defined $reason || length($reason) < 255));
  return sendClient($self,$hdl,['SERVERMSG','Cannot ban account, feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{BAN});
  my %DURATION_SUFFIXES=(
    y => 525600,
    m => 43200,
    w => 10080,
    d => 1440,
    h => 60,
      );
  foreach my $durationSuffix (keys %DURATION_SUFFIXES) {
    if($duration =~ /^(\d+)$durationSuffix$/) {
      $duration = $1 * $DURATION_SUFFIXES{$durationSuffix};
      last;
    }
  }
  $self->{accountManagementSvc}{BAN}(
    sub {
      my ($failedReason,$bannedAccountId)=@_;
      my @inducedTraffic;
      if(defined $failedReason) {
        return if($hdl->destroyed());
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to ban '.$userName.': '.$failedReason],$cmdId);
      }else{
        # banned user may have disconnected, reconnected and even renamed during async processing...
        my $currentBannedUserName=getOnlineClientName($self,$bannedAccountId,$userName);
        @inducedTraffic=kickUserFromServer($self,$currentBannedUserName,$login,$reason,1) if(defined $currentBannedUserName);
        return if($hdl->destroyed());
        addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['SERVERMSG','Banned '.$userName.' from the server'],$cmdId));
      }
      closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
    },
    $r_connInfo,$login,$r_userInfo,$userName,$duration,$reason,
  );
  return;
}

sub hUnban {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $userName=$r_cmd->[1];
  return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid UNBAN parameter'],$cmdId)
      unless($userName =~ REGEX_USERNAME);
  return sendClient($self,$hdl,['SERVERMSG','Cannot unban account, feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{UNBAN});
  $self->{accountManagementSvc}{UNBAN}(
    sub {
      return if($hdl->destroyed());
      my $failedReason=shift;
      my @inducedTraffic;
      if(defined $failedReason) {
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to unban '.$userName.': '.$failedReason],$cmdId);
      }else{
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Unbanned '.$userName.' from the server'],$cmdId);
      }
      closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
    },
    $r_connInfo,$login,$r_userInfo,$userName,
  );
  return;
}

sub hListBans {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  return sendClient($self,$hdl,['SERVERMSG','Cannot list bans, feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{LISTBANS});
  $self->{accountManagementSvc}{LISTBANS}(
    sub {
      return if($hdl->destroyed());
      my ($failedReason,$r_bans)=@_;
      my @inducedTraffic;
      if(defined $failedReason) {
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to list bans: '.$failedReason],$cmdId);
      }else{
        if(defined $r_bans && @{$r_bans}) {
          my @serverMsgs=('-- Banlist --');
          foreach my $r_ban (@{$r_bans}) {
            push(@serverMsgs,'. '.join(', ',map {$_.':'.$r_ban->{$_}} (sort keys %{$r_ban})));
          }
          push(@serverMsgs,'-- End Banlist --');
          @inducedTraffic=sendClientMulti($self,$hdl,[map {['SERVERMSG',$_]} @serverMsgs],$cmdId);
        }else{
          @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Banlist is empty'],$cmdId);
        }
      }
      closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
    },
    $r_connInfo,$login,$r_userInfo
  );
  return;
}

sub hSetAccess {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$userName,$accessLevel)=@{$r_cmd};
  return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid SETACCESS parameter (userName)'],$cmdId)
      unless($userName =~ REGEX_USERNAME);
  my $lcAccessLevel=lc($accessLevel);
  my %ACCESS_MODES=(
    user => 1,
    mod => 100,
    admin => 200,
      );
  if(exists $ACCESS_MODES{$lcAccessLevel}) {
    $accessLevel=$ACCESS_MODES{$lcAccessLevel};
  }elsif($accessLevel !~ /^\d{1,6}$/) {
    return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid SETACCESS parameter (accessLevel)'],$cmdId)
  }
  my $r_updatedUserInfo=$self->{users}{$userName};
  return sendClient($self,$hdl,['SERVERMSG','Failed to set access level for '.$userName.': access is already set to '.$accessLevel],$cmdId)
      if(defined $r_updatedUserInfo && $r_updatedUserInfo->{accessLevel} == $accessLevel);
  my $newAccessFlag;
  if($self->{accessFlagLevel}) {
    $newAccessFlag = $accessLevel >= $self->{accessFlagLevel} ? 1 : 0;
  }
  if(exists $self->{accountManagementSvc}{SETACCESS}) {
    $self->{accountManagementSvc}{SETACCESS}(
      sub {
        my ($failedReason,$updatedAccountId)=@_;
        my @inducedTraffic;
        if(defined $failedReason) {
          return if($hdl->destroyed());
          @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to set access level for '.$userName.': '.$failedReason],$cmdId);
        }else{
          # updated client may have disconnected, reconnected and even renamed during async processing...
          my ($currentUserName,$r_currentUserInfo)=getOnlineClientData($self,$updatedAccountId,$userName);
          if(defined $r_currentUserInfo) {
            $r_currentUserInfo->{accessLevel}=$accessLevel;
            if(defined $newAccessFlag && $r_currentUserInfo->{status}{access} != $newAccessFlag) {
              $r_currentUserInfo->{status}{access}=$newAccessFlag;
              $r_currentUserInfo->{marshalledStatus}=marshallClientStatus($r_currentUserInfo->{status});
              @inducedTraffic=broadcast($self,'CLIENTSTATUS',$currentUserName,$r_currentUserInfo->{marshalledStatus});
            }
          }
          return if($hdl->destroyed());
          addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['SERVERMSG','Access level for '.$userName.' successfully set to '.$accessLevel],$cmdId));
        }
        closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      },
      $r_connInfo,$login,$r_userInfo,$userName,$accessLevel,
    );
    return;
  }elsif(defined $r_updatedUserInfo) {
    my @inducedTraffic;
    $r_updatedUserInfo->{accessLevel}=$accessLevel;
    if(defined $newAccessFlag && $r_updatedUserInfo->{status}{access} != $newAccessFlag) {
      $r_updatedUserInfo->{status}{access} = $newAccessFlag;
      $r_updatedUserInfo->{marshalledStatus}=marshallClientStatus($r_updatedUserInfo->{status});
      @inducedTraffic=broadcast($self,'CLIENTSTATUS',$userName,$r_updatedUserInfo->{marshalledStatus});
    }
    addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['SERVERMSG','Access level for '.$userName.' successfully set to '.$accessLevel],$cmdId));
    return @inducedTraffic;
  }else{
    return sendClient($self,$hdl,['SERVERMSG','Cannot set access level of offline client, feature is not supported by this server'],$cmdId);
  }
}

sub hDeleteAccount {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my $userName=$r_cmd->[1];
  return sendClient($self,$hdl,['SERVERMSG','Protocol error: invalid DELETEACCOUNT parameter'],$cmdId)
      unless($userName =~ REGEX_USERNAME);
  return sendClient($self,$hdl,['SERVERMSG','Cannot delete account, feature is not supported by this server'],$cmdId)
      unless(exists $self->{accountManagementSvc}{DELETEACCOUNT});
  $self->{accountManagementSvc}{DELETEACCOUNT}(
    sub {
      my ($failedReason,$deletedAccountId)=@_;
      my @inducedTraffic;
      if(defined $failedReason) {
        return if($hdl->destroyed());
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to delete account of '.$userName.': '.$failedReason],$cmdId);
      }else{
        # client may have disconnected, reconnected and even renamed during async processing...
        my $currentDeletedUserName=getOnlineClientName($self,$deletedAccountId,$userName);
        @inducedTraffic=kickUserFromServer($self,$currentDeletedUserName,$login,'account deleted') if(defined $currentDeletedUserName);
        return if($hdl->destroyed());
        addInducedTraffic(\@inducedTraffic,sendClient($self,$hdl,['SERVERMSG','Deleted account of '.$userName],$cmdId));
      }
      closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
    },
    $r_connInfo,$login,$r_userInfo,$userName,
  );
  return;
}

sub hIgnore {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@tagParamDefs)=@{$r_cmd};
  my ($r_tagParams,$paramError)=parseTagParamDefs(\@tagParamDefs,['userName','reason']);
  return closeClientConnection($self,$hdl,'protocol error','invalid IGNORE parameter: '.$paramError)
      if(defined $paramError);
  my ($userName,$reason)=@{$r_tagParams}{qw'userName reason'};
  return closeClientConnection($self,$hdl,'protocol error','missing IGNORE parameter: userName')
      unless(defined $userName);
  return closeClientConnection($self,$hdl,'protocol error','invalid IGNORE parameter')
      unless($userName =~ REGEX_USERNAME
             && (! defined $reason || length($reason) < 255));
  my $accountId=$r_userInfo->{accountId};
  return sendClient($self,$hdl,['SERVERMSG','Cannot ignore account, feature requires accountId feature which is not supported by this server'],$cmdId)
      unless($accountId);
  my $ignoredAccountId;
  if(exists $self->{users}{$userName}) {
    $ignoredAccountId=$self->{users}{$userName}{accountId};
    return sendClient($self,$hdl,['SERVERMSG','Cannot ignore account, feature requires accountId feature which is not fully supported by this server'],$cmdId)
        unless($ignoredAccountId);
    return sendClient($self,$hdl,['SERVERMSG','Failed to ignore '.$userName.': account is already ignored'],$cmdId)
        if(exists $r_userInfo->{ignoredAccounts}{$ignoredAccountId});
  }
  return sendClient($self,$hdl,['SERVERMSG','Cannot ignore more accounts: maximum number of ignored accounts reached'],$cmdId)
      if($self->{maxIgnoresByAccount} && keys %{$r_userInfo->{ignoredAccounts}} >= $self->{maxIgnoresByAccount});
  if(exists $self->{ignoreSvc}{IGNORE}) {
    $self->{ignoreSvc}{IGNORE}(
      sub {
        my ($failedReason,$ignoredAccountIdFromDb)=@_;
        my @inducedTraffic;
        if(defined $failedReason) {
          return if($hdl->destroyed());
          @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to ignore '.$userName.': '.$failedReason],$cmdId);
        }else{
          # client may have disconnected, reconnected and even renamed during async processing...
          my (undef,$r_currentUserInfo)=getOnlineClientData($self,$accountId);
          return unless(defined $r_currentUserInfo && ! exists $r_currentUserInfo->{ignoredAccounts}{$ignoredAccountIdFromDb});
          $r_currentUserInfo->{ignoredAccounts}{$ignoredAccountIdFromDb}=$r_tagParams;
          return if($hdl->destroyed()); # do not send command ack if user reconnected
          @inducedTraffic=sendClient($self,$hdl,$r_cmd,$cmdId);
        }
        closeClientConnection($self,$hdl,'induced traffic flood')
            if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      },
      $r_connInfo,$login,$r_userInfo,$userName,$reason,
    );
    return;
  }elsif(defined $ignoredAccountId) {
    $r_userInfo->{ignoredAccounts}{$ignoredAccountId}=$r_tagParams;
    return sendClient($self,$hdl,$r_cmd,$cmdId);
  }else{
    return sendClient($self,$hdl,['SERVERMSG','Cannot ignore offline account, feature is not supported by this server'],$cmdId);
  }
}

sub parseTagParamDefs {
  my ($r_tagParamDefs,$r_allowedTags)=@_;
  my $r_tagParams={};
  foreach my $tagParamDef (@{$r_tagParamDefs}) {
    if($tagParamDef =~ REGEX_TAGPARAM) {
      my ($paramName,$paramVal)=($1,$2);
      return (undef,'duplicate tag parameter')
          if(exists $r_tagParams->{$paramName});
      return (undef,'wrong tag parameter name')
          if(none {$paramName eq $_} @{$r_allowedTags});
      $r_tagParams->{$paramName}=$paramVal;
    }else{
      return (undef,'wrong tag parameter syntax');
    }
  }
  return ($r_tagParams);
}

sub hUnignore {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@tagParamDefs)=@{$r_cmd};
  my ($r_tagParams,$paramError)=parseTagParamDefs(\@tagParamDefs,['userName']);
  return closeClientConnection($self,$hdl,'protocol error','invalid UNIGNORE parameter: '.$paramError)
      if(defined $paramError);
  my $userName=$r_tagParams->{userName};
  return closeClientConnection($self,$hdl,'protocol error','missing UNIGNORE parameter: userName')
      unless(defined $userName);
  return closeClientConnection($self,$hdl,'protocol error','invalid UNIGNORE parameter')
      unless($userName =~ REGEX_USERNAME);
  my $accountId=$r_userInfo->{accountId};
  return sendClient($self,$hdl,['SERVERMSG','Cannot unignore account, feature requires accountId feature which is not supported by this server'],$cmdId)
      unless($accountId);
  my $ignoredAccountId;
  if(exists $self->{users}{$userName}) {
    $ignoredAccountId=$self->{users}{$userName}{accountId};
    return sendClient($self,$hdl,['SERVERMSG','Cannot unignore account, feature requires accountId feature which is not fully supported by this server'],$cmdId)
        unless($ignoredAccountId);
    return sendClient($self,$hdl,['SERVERMSG','Failed to unignore '.$userName.': account is not ignored'],$cmdId)
        unless(exists $r_userInfo->{ignoredAccounts}{$ignoredAccountId});
  }
  if(exists $self->{ignoreSvc}{UNIGNORE}) {
    $self->{ignoreSvc}{UNIGNORE}(
      sub {
        my ($failedReason,$ignoredAccountIdFromDb)=@_;
        my @inducedTraffic;
        if(defined $failedReason) {
          return if($hdl->destroyed());
          @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to unignore '.$userName.': '.$failedReason],$cmdId);
        }else{
          # client may have disconnected, reconnected and even renamed during async processing...
          my (undef,$r_currentUserInfo)=getOnlineClientData($self,$accountId);
          return unless(defined $r_currentUserInfo && exists $r_currentUserInfo->{ignoredAccounts}{$ignoredAccountIdFromDb});
          delete $r_currentUserInfo->{ignoredAccounts}{$ignoredAccountIdFromDb};
          return if($hdl->destroyed()); # do not send command ack if user reconnected
          @inducedTraffic=sendClient($self,$hdl,$r_cmd,$cmdId);
        }
        closeClientConnection($self,$hdl,'induced traffic flood')
            if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      },
      $r_connInfo,$login,$r_userInfo,$userName,
    );
    return;
  }elsif(defined $ignoredAccountId) {
    delete $r_userInfo->{ignoredAccounts}{$ignoredAccountId};
    return sendClient($self,$hdl,$r_cmd,$cmdId);
  }else{
    my $unignoredAccounts=0;
    foreach my $ignoredId (keys %{$r_userInfo->{ignoredAccounts}}) {
      if($r_userInfo->{ignoredAccounts}{$ignoredId}{userName} eq $userName) {
        delete $r_userInfo->{ignoredAccounts}{$ignoredId};
        $unignoredAccounts++;
      }
    }
    if($unignoredAccounts) {
      return sendClient($self,$hdl,$r_cmd,$cmdId);
    }else{
      return sendClient($self,$hdl,['SERVERMSG','Failed to unignore '.$userName.': user is not ignored'],$cmdId)
    }
  }
}

sub hIgnoreList {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  if(exists $self->{ignoreSvc}{IGNORELIST}) {
    $self->{ignoreSvc}{IGNORELIST}(
      sub {
        return if($hdl->destroyed());
        my $r_ignoreList=shift;
        my @ignoreListCmds=(['IGNORELISTBEGIN']);
        if(defined $r_ignoreList) {
          foreach my $r_ignoreData (@{$r_ignoreList}) {
            my @tagParams=('userName='.$r_ignoreData->{userName});
            push(@tagParams,'reason='.$r_ignoreData->{reason}) if(defined $r_ignoreData->{reason});
            push(@tagParams,'accountId='.$r_ignoreData->{accountId}) if(defined $r_ignoreData->{accountId});
            push(@ignoreListCmds,['IGNORELIST',@tagParams]);
          }
        }
        push(@ignoreListCmds,['IGNORELISTEND']);
        my @inducedTraffic=sendClientMulti($self,$hdl,\@ignoreListCmds,$cmdId);
        closeClientConnection($self,$hdl,'induced traffic flood')
            if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      },
      $r_connInfo,$login,$r_userInfo);
    return;
  }else{
    my @ignoreListCmds=(['IGNORELISTBEGIN']);
    foreach my $ignoredId (sort keys %{$r_userInfo->{ignoredAccounts}}) {
      my $r_ignoreData=$r_userInfo->{ignoredAccounts}{$ignoredId};
      my @tagParams=('userName='.($self->{accounts}{$ignoredId}//$r_ignoreData->{userName}));
      my $reason=$r_ignoreData->{reason};
      push(@tagParams,'reason='.$reason) if(defined $reason);
      push(@tagParams,'accountId='.$ignoredId);
      push(@ignoreListCmds,['IGNORELIST',@tagParams]);
    }
    push(@ignoreListCmds,['IGNORELISTEND']);
    return sendClientMulti($self,$hdl,\@ignoreListCmds,$cmdId);
  }
}

sub hFriendRequest {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@tagParamDefs)=@{$r_cmd};
  my ($r_tagParams,$paramError)=parseTagParamDefs(\@tagParamDefs,['userName','msg']);
  return closeClientConnection($self,$hdl,'protocol error','invalid FRIENDREQUEST parameter: '.$paramError)
      if(defined $paramError);
  my ($userName,$msg)=@{$r_tagParams}{qw'userName msg'};
  return closeClientConnection($self,$hdl,'protocol error','missing FRIENDREQUEST parameter: userName')
      unless(defined $userName);
  return closeClientConnection($self,$hdl,'protocol error','invalid FRIENDREQUEST parameter')
      unless($userName =~ REGEX_USERNAME
             && (! defined $msg || length($msg) < 255));
  return sendClient($self,$hdl,['SERVERMSG','Cannot send friend request, feature is not supported by this server'],$cmdId)
      unless(exists $self->{friendSvc}{FRIENDREQUEST});
  return sendClient($self,$hdl,['SERVERMSG','Cannot send friend request to yourself'],$cmdId)
      if($login eq $userName);
  my $accountId=$r_userInfo->{accountId};
  return sendClient($self,$hdl,['SERVERMSG','Cannot send friend request, feature requires accountId feature which is not supported by this server'],$cmdId)
      unless($accountId);
  if(exists $self->{users}{$userName}) {
    my $r_friendUserInfo=$self->{users}{$userName};
    my $friendAccountId=$r_friendUserInfo->{accountId};
    return sendClient($self,$hdl,['SERVERMSG','Cannot send friend request, feature requires accountId feature which is not fully supported by this server'],$cmdId)
        unless($friendAccountId);
    return sendClient($self,$hdl,['SERVERMSG','Failed to send friend request to '.$userName.': already friend'],$cmdId)
        if(exists $r_userInfo->{friendAccounts}{$friendAccountId});
    return sendClient($self,$hdl,['SERVERMSG','Failed to send friend request to '.$userName.': you already have an incoming friend request from this user, use ACCEPTFRIENDREQUEST instead'],$cmdId)
        if(exists $r_userInfo->{friendRequestsIn}{$friendAccountId});
    return if(exists $r_friendUserInfo->{friendRequestsIn}{$accountId} || exists $r_friendUserInfo->{ignoredAccounts}{$accountId});
    return sendClient($self,$hdl,['SERVERMSG','Failed to send friend request to '.$userName.': user has reached maximum number of friends and friend requests'],$cmdId)
      if($self->{maxFriendsByAccount} && keys(%{$r_friendUserInfo->{friendAccounts}}) + keys(%{$r_friendUserInfo->{friendRequestsIn}}) + keys(%{$r_friendUserInfo->{friendRequestsOut}}) >= $self->{maxFriendsByAccount});
  }
  return sendClient($self,$hdl,['SERVERMSG','Cannot send friend request: maximum number of friends and friend requests reached'],$cmdId)
      if($self->{maxFriendsByAccount} && keys(%{$r_userInfo->{friendAccounts}}) + keys(%{$r_userInfo->{friendRequestsIn}}) + keys(%{$r_userInfo->{friendRequestsOut}}) >= $self->{maxFriendsByAccount});
  $self->{friendSvc}{FRIENDREQUEST}(
    sub {
      my ($failedReason,$friendAccountId)=@_;
      my @inducedTraffic;
      if(defined $failedReason) {
        return if($hdl->destroyed());
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to send friend request to '.$userName.': '.$failedReason],$cmdId) unless($failedReason eq '');
      }else{
        # clients may have disconnected, reconnected and even renamed during async processing...
        my ($friendUserName,$r_friendUserInfo)=getOnlineClientData($self,$friendAccountId);
        $friendUserName//=$userName;
        my ($currentLogin,$r_currentUserInfo)=getOnlineClientData($self,$accountId);
        $currentLogin//=$login;
        # we don't check ignoredAccounts here to keep consistency with DB (avoid race conditions)
        if(defined $r_currentUserInfo
           && ! exists $r_currentUserInfo->{friendAccounts}{$friendAccountId}
           && ! exists $r_currentUserInfo->{friendRequestsOut}{$friendAccountId}
           && ! exists $r_currentUserInfo->{friendRequestsIn}{$friendAccountId}) {
          my %friendData=(userName => $friendUserName);
          $friendData{msg}=$msg if(defined $msg);
          $r_currentUserInfo->{friendRequestsOut}{$friendAccountId}=\%friendData;
        }
        if(defined $r_friendUserInfo
           && ! exists $r_friendUserInfo->{friendAccounts}{$accountId}
           && ! exists $r_friendUserInfo->{friendRequestsOut}{$accountId}
           && ! exists $r_friendUserInfo->{friendRequestsIn}{$accountId}) {
          my %friendData=(userName => $currentLogin);
          $friendData{msg}=$msg if(defined $msg);
          $r_friendUserInfo->{friendRequestsIn}{$accountId}=\%friendData;
          my @tagParams=('userName='.$currentLogin);
          push(@tagParams,'msg='.$msg) if(defined $msg);
          push(@tagParams,'accountId='.$accountId);
          @inducedTraffic=sendUser($self,$friendUserName,['FRIENDREQUEST',@tagParams]);
        }
        return if($hdl->destroyed());
      }
      closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      
    },
    $r_connInfo,$login,$r_userInfo,$userName,$msg,
  );
  return;
}

sub hAcceptFriendRequest {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@tagParamDefs)=@{$r_cmd};
  my ($r_tagParams,$paramError)=parseTagParamDefs(\@tagParamDefs,['userName']);
  return closeClientConnection($self,$hdl,'protocol error','invalid ACCEPTFRIENDREQUEST parameter: '.$paramError)
      if(defined $paramError);
  my $userName=$r_tagParams->{userName};
  return closeClientConnection($self,$hdl,'protocol error','missing ACCEPTFRIENDREQUEST parameter: userName')
      unless(defined $userName);
  return closeClientConnection($self,$hdl,'protocol error','invalid ACCEPTFRIENDREQUEST parameter')
      unless($userName =~ REGEX_USERNAME);
  return sendClient($self,$hdl,['SERVERMSG','Cannot accept friend request, feature is not supported by this server'],$cmdId)
      unless(exists $self->{friendSvc}{ACCEPTFRIENDREQUEST});
  my $accountId=$r_userInfo->{accountId};
  return sendClient($self,$hdl,['SERVERMSG','Cannot accept friend request, feature requires accountId feature which is not supported by this server'],$cmdId)
      unless($accountId);
  if(exists $self->{users}{$userName}) {
    my $friendAccountId=$self->{users}{$userName}{accountId};
    return sendClient($self,$hdl,['SERVERMSG','Cannot accept friend request, feature requires accountId feature which is not fully supported by this server'],$cmdId)
        unless($friendAccountId);
    return sendClient($self,$hdl,['SERVERMSG','Failed to accept friend request, no pending request from '.$userName],$cmdId)
        unless(exists $r_userInfo->{friendRequestsIn}{$friendAccountId});
    if(exists $r_userInfo->{friendAccounts}{$friendAccountId}) {
      delete $r_userInfo->{friendRequestsIn}{$friendAccountId};
      return;
    }
  }
  $self->{friendSvc}{ACCEPTFRIENDREQUEST}(
    sub {
      my ($failedReason,$friendAccountId)=@_;
      my @inducedTraffic;
      if(defined $failedReason) {
        return if($hdl->destroyed());
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to accept friend request from '.$userName.': '.$failedReason],$cmdId);
      }else{
        # clients may have disconnected, reconnected and even renamed during async processing...
        my ($friendUserName,$r_friendUserInfo)=getOnlineClientData($self,$friendAccountId);
        $friendUserName//=$userName;
        my ($currentLogin,$r_currentUserInfo)=getOnlineClientData($self,$accountId);
        $currentLogin//=$login;
        if(defined $r_currentUserInfo) {
          delete $r_currentUserInfo->{friendRequestsIn}{$friendAccountId};
          if(! exists $r_currentUserInfo->{friendAccounts}{$friendAccountId}) {
            $r_currentUserInfo->{friendAccounts}{$friendAccountId}=$friendUserName;
            @inducedTraffic=sendUser($self,$currentLogin,['FRIEND','userName='.$friendUserName,'accountId='.$friendAccountId]);
          }
        }
        if(defined $r_friendUserInfo) {
          delete $r_friendUserInfo->{friendRequestsOut}{$accountId};
          if(! exists $r_friendUserInfo->{friendAccounts}{$accountId}) {
            $r_friendUserInfo->{friendAccounts}{$accountId}=$currentLogin;
            addInducedTraffic(\@inducedTraffic,sendUser($self,$friendUserName,['FRIEND','userName='.$currentLogin,'accountId='.$accountId]));
          }
        }
        return if($hdl->destroyed());
      }
      closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
    },
    $r_connInfo,$login,$r_userInfo,$userName,
  );
  return;
}

sub hDeclineFriendRequest {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@tagParamDefs)=@{$r_cmd};
  my ($r_tagParams,$paramError)=parseTagParamDefs(\@tagParamDefs,['userName']);
  return closeClientConnection($self,$hdl,'protocol error','invalid DECLINEFRIENDREQUEST parameter: '.$paramError)
      if(defined $paramError);
  my $userName=$r_tagParams->{userName};
  return closeClientConnection($self,$hdl,'protocol error','missing DECLINEFRIENDREQUEST parameter: userName')
      unless(defined $userName);
  return closeClientConnection($self,$hdl,'protocol error','invalid DECLINEFRIENDREQUEST parameter')
      unless($userName =~ REGEX_USERNAME);
  return sendClient($self,$hdl,['SERVERMSG','Cannot decline friend request, feature is not supported by this server'],$cmdId)
      unless(exists $self->{friendSvc}{DECLINEFRIENDREQUEST});
  my $accountId=$r_userInfo->{accountId};
  return sendClient($self,$hdl,['SERVERMSG','Cannot decline friend request, feature requires accountId feature which is not supported by this server'],$cmdId)
      unless($accountId);
  if(exists $self->{users}{$userName}) {
    my $friendAccountId=$self->{users}{$userName}{accountId};
    return sendClient($self,$hdl,['SERVERMSG','Cannot decline friend request, feature requires accountId feature which is not fully supported by this server'],$cmdId)
        unless($friendAccountId);
    return sendClient($self,$hdl,['SERVERMSG','Failed to decline friend request, no pending request from '.$userName],$cmdId)
        unless(exists $r_userInfo->{friendRequestsIn}{$friendAccountId});
    if(exists $r_userInfo->{friendAccounts}{$friendAccountId}) {
      delete $r_userInfo->{friendRequestsIn}{$friendAccountId};
      return;
    }
  }
  $self->{friendSvc}{DECLINEFRIENDREQUEST}(
    sub {
      my ($failedReason,$friendAccountId)=@_;
      if(defined $failedReason) {
        return if($hdl->destroyed());
        my @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to decline friend request from '.$userName.': '.$failedReason],$cmdId);
        closeClientConnection($self,$hdl,'induced traffic flood')
            if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      }else{
        # clients may have disconnected, reconnected and even renamed during async processing...
        my (undef,$r_friendUserInfo)=getOnlineClientData($self,$friendAccountId);
        delete $r_friendUserInfo->{friendRequestsOut}{$accountId} if(defined $r_friendUserInfo);
        my (undef,$r_currentUserInfo)=getOnlineClientData($self,$accountId);
        delete $r_currentUserInfo->{friendRequestsIn}{$friendAccountId} if(defined $r_currentUserInfo);
      }
    },
    $r_connInfo,$login,$r_userInfo,$userName,
  );
  return;
}

sub hUnfriend {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@tagParamDefs)=@{$r_cmd};
  my ($r_tagParams,$paramError)=parseTagParamDefs(\@tagParamDefs,['userName']);
  return closeClientConnection($self,$hdl,'protocol error','invalid UNFRIEND parameter: '.$paramError)
      if(defined $paramError);
  my $userName=$r_tagParams->{userName};
  return closeClientConnection($self,$hdl,'protocol error','missing UNFRIEND parameter: userName')
      unless(defined $userName);
  return closeClientConnection($self,$hdl,'protocol error','invalid UNFRIEND parameter')
      unless($userName =~ REGEX_USERNAME);
  return sendClient($self,$hdl,['SERVERMSG','Cannot unfriend, feature is not supported by this server'],$cmdId)
      unless(exists $self->{friendSvc}{UNFRIEND});
  my $accountId=$r_userInfo->{accountId};
  return sendClient($self,$hdl,['SERVERMSG','Cannot unfriend, feature requires accountId feature which is not supported by this server'],$cmdId)
      unless($accountId);
  if(exists $self->{users}{$userName}) {
    my $friendAccountId=$self->{users}{$userName}{accountId};
    return sendClient($self,$hdl,['SERVERMSG','Cannot unfriend, feature requires accountId feature which is not fully supported by this server'],$cmdId)
        unless($friendAccountId);
    return sendClient($self,$hdl,['SERVERMSG','Failed to unfriend, not friend with '.$userName],$cmdId)
        unless(exists $r_userInfo->{friendAccounts}{$friendAccountId});
  }
  $self->{friendSvc}{UNFRIEND}(
    sub {
      my ($failedReason,$friendAccountId)=@_;
      my @inducedTraffic;
      if(defined $failedReason) {
        return if($hdl->destroyed());
        @inducedTraffic=sendClient($self,$hdl,['SERVERMSG','Failed to unfriend with '.$userName.': '.$failedReason],$cmdId);
      }else{
        # clients may have disconnected, reconnected and even renamed during async processing...
        my ($friendUserName,$r_friendUserInfo)=getOnlineClientData($self,$friendAccountId);
        $friendUserName//=$userName;
        my ($currentLogin,$r_currentUserInfo)=getOnlineClientData($self,$accountId);
        $currentLogin//=$login;
        if(defined $r_currentUserInfo && exists $r_currentUserInfo->{friendAccounts}{$friendAccountId}) {
          delete $r_currentUserInfo->{friendAccounts}{$friendAccountId};
          @inducedTraffic=sendUser($self,$currentLogin,['UNFRIEND','userName='.$friendUserName,'accountId='.$friendAccountId]);
        }
        if(defined $r_friendUserInfo && exists $r_friendUserInfo->{friendAccounts}{$accountId}) {
          delete $r_friendUserInfo->{friendAccounts}{$accountId};
          addInducedTraffic(\@inducedTraffic,sendUser($self,$friendUserName,['UNFRIEND','userName='.$currentLogin,'accountId='.$accountId]));
        }
        return if($hdl->destroyed());
      }
      closeClientConnection($self,$hdl,'induced traffic flood')
          if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
    },
    $r_connInfo,$login,$r_userInfo,$userName,
  );
  return;
}

sub hFriendRequestList {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,@tagParamDefs)=@{$r_cmd};
  my ($r_tagParams,$paramError)=parseTagParamDefs(\@tagParamDefs,['type']);
  return closeClientConnection($self,$hdl,'protocol error','invalid FRIENDREQUESTLIST parameter: '.$paramError)
      if(defined $paramError);
  my $isOutgoingRequests;
  my $type=$r_tagParams->{type};
  if(defined $type) {
    if(lc($type) eq 'in') {
      $type='in';
    }elsif(lc($type) eq 'out') {
      $isOutgoingRequests=1;
      $type='out';
    }else{
      closeClientConnection($self,$hdl,'protocol error','invalid FRIENDREQUESTLIST parameter: type');
    }
  }
  if(exists $self->{friendSvc}{FRIENDREQUESTLIST}) {
    $self->{friendSvc}{FRIENDREQUESTLIST}(
      sub {
        return if($hdl->destroyed());
        my $r_friendRequestList=shift;
        my @friendCmds=(['FRIENDREQUESTLISTBEGIN']);
        if(defined $r_friendRequestList) {
          foreach my $r_friendData (@{$r_friendRequestList}) {
            my @tagParams=('userName='.$r_friendData->{userName});
            map {push(@tagParams,$_.'='.$r_friendData->{$_}) if(defined $r_friendData->{$_})} (qw'msg accountId type');
            push(@friendCmds,['FRIENDREQUESTLIST',@tagParams]);
          }
        }
        push(@friendCmds,['FRIENDREQUESTLISTEND']);
        my @inducedTraffic=sendClientMulti($self,$hdl,\@friendCmds,$cmdId);
        closeClientConnection($self,$hdl,'induced traffic flood')
            if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      },
      $r_connInfo,$login,$r_userInfo,$isOutgoingRequests);
    return;
  }else{
    my $friendRequestsField = $isOutgoingRequests ? 'friendRequestsOut' : 'friendRequestsIn';
    my @friendCmds=(['FRIENDREQUESTLISTBEGIN']);
    foreach my $friendAccountId (sort keys %{$r_userInfo->{$friendRequestsField}}) {
      my $r_friendData=$r_userInfo->{$friendRequestsField}{$friendAccountId};
      my @tagParams=('userName='.$r_friendData->{userName});
      push(@tagParams,'msg='.$r_friendData->{msg}) if(defined $r_friendData->{msg});
      push(@tagParams,'accountId='.$friendAccountId);
      push(@tagParams,'type='.$type) if(defined $type);
      push(@friendCmds,['FRIENDREQUESTLIST',@tagParams]);
    }
    push(@friendCmds,['FRIENDREQUESTLISTEND']);
    return sendClientMulti($self,$hdl,\@friendCmds,$cmdId);
  }
}

sub hFriendList {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  if(exists $self->{friendSvc}{FRIENDLIST}) {
    $self->{friendSvc}{FRIENDLIST}(
      sub {
        return if($hdl->destroyed());
        my $r_friendList=shift;
        my @friendCmds=(['FRIENDLISTBEGIN']);
        if(defined $r_friendList) {
          foreach my $r_friendData (@{$r_friendList}) {
            my @tagParams=('userName='.$r_friendData->{userName});
            push(@tagParams,'accountId='.$r_friendData->{accountId}) if(defined $r_friendData->{accountId});
            push(@friendCmds,['FRIENDLIST',@tagParams]);
          }
        }
        push(@friendCmds,['FRIENDLISTEND']);
        my @inducedTraffic=sendClientMulti($self,$hdl,\@friendCmds,$cmdId);
        closeClientConnection($self,$hdl,'induced traffic flood')
            if($inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      },
      $r_connInfo,$login,$r_userInfo);
    return;
  }else{
    my @friendCmds=(['FRIENDLISTBEGIN']);
    map {push(@friendCmds,['FRIENDLIST','userName='.$r_userInfo->{friendAccounts}{$_},'accountId='.$_])} (sort keys %{$r_userInfo->{friendAccounts}});
    push(@friendCmds,['FRIENDLISTEND']);
    return sendClientMulti($self,$hdl,\@friendCmds,$cmdId);
  }
}

sub hChannelTopic {
  my ($self,$hdl,$r_connInfo,$login,$r_userInfo,$r_cmd,$cmdId)=@_;
  my (undef,$chan,$topic)=@{$r_cmd};
  return closeClientConnection($self,$hdl,'protocol error','invalid CHANNELTOPIC parameter')
      unless($chan =~ REGEX_CHANNEL
             && length($topic) <= $self->{maxChatMsgLength});
  $topic='' if($topic eq '*');
  if(defined $self->{onChannelTopic}) {
    my $denyMsg=$self->{onChannelTopic}($r_connInfo,$login,$r_userInfo,$chan,\$topic);
    if(defined $denyMsg) {
      return if($denyMsg eq '');
      return sendClient($self,$hdl,['SERVERMSG',"Failed to set channel topic for channel \"$chan\": $denyMsg"],$cmdId);
    }
  }
  if(defined $self->{onChannelTopicAsync}) {
    $self->{onChannelTopicAsync}->(
      sub {
        my $denyMsg=shift;
        if(defined $denyMsg) {
          return if($hdl->destroyed() || $denyMsg eq '');
          return sendClient($self,$hdl,['SERVERMSG',"Failed to set channel topic for channel \"$chan\": $denyMsg"],$cmdId);
        }
        my @inducedTraffic=updateChannelTopic($self,$chan,$topic,$login);
        closeClientConnection($self,$hdl,'induced traffic flood')
            if(! $hdl->destroyed() && $inducedTraffic[0] && defined checkInducedTrafficFlood($self,$r_userInfo,@inducedTraffic));
      },
      $r_connInfo,$login,$r_userInfo,$chan,\$topic);
  }else{
    return updateChannelTopic($self,$chan,$topic,$login);
  }
}

sub updateChannelTopic {
  my ($self,$chan,$topic,$author)=@_;
  if(exists $self->{channelTopics}{$chan}) {
    return if($self->{channelTopics}{$chan}{topic} eq $topic);
    if($topic eq '') {
      delete $self->{channelTopics}{$chan};
    }else{
      $self->{channelTopics}{$chan}={topic => $topic, author => $author};
    }
  }else{
    return if($topic eq '');
    $self->{channelTopics}{$chan}={topic => $topic, author => $author};
  }
  my @inducedTraffic=broadcastChannelLegacy($self,$chan,['CHANNELTOPIC',$chan,$author,$topic],['CHANNELTOPIC',$chan,$author,time()*1000,$topic eq '' ? '<null>' : $topic]);
  addInducedTraffic(\@inducedTraffic,broadcastChannel($self,$chan,'CHANNELMESSAGE',$chan,$topic eq '' ? 'Topic removed.' : 'Topic changed.'));
  return @inducedTraffic
}

sub srvBotAdd {
  my ($self,$srvBot,$r_onPrivateMsg,$r_onChannelMsg,$r_srvBotInfo,$r_srvBotStatus)=@_;
  my $lcBotName=lc($srvBot);
  croak "invalid srvBotAdd call: duplicate server bot \"$srvBot\"" if(exists $self->{lcServerBots}{$lcBotName});
  croak "invalid srvBotAdd call: username conflict for server bot \"$srvBot\"" if(exists $self->{lcUsers}{$lcBotName});
  my %srvBotInfo;
  if(defined $r_srvBotInfo) {
    map {$srvBotInfo{$_}=$r_srvBotInfo->{$_}//$DEFAULT_SRVBOT_INFO{$_}} (keys %DEFAULT_SRVBOT_INFO);
    $srvBotInfo{country}//=$self->{defaultCountryCode};
  }else{
    %srvBotInfo=%DEFAULT_SRVBOT_INFO;
    $srvBotInfo{country}=$self->{defaultCountryCode};
  }
  my %srvBotStatus;
  if(defined $r_srvBotStatus) {
    map {$srvBotStatus{$_}=$r_srvBotStatus->{$_}//$DEFAULT_SRVBOT_STATUS{$_}} (keys %DEFAULT_SRVBOT_STATUS);
  }else{
    %srvBotStatus=%DEFAULT_SRVBOT_STATUS;
  }
  my $marshalledBotStatus=marshallClientStatus(\%srvBotStatus);
  @srvBotInfo{qw'status marshalledStatus channels onPrivateMsg onChannelMsg'}=(\%srvBotStatus,$marshalledBotStatus,{},$r_onPrivateMsg,$r_onChannelMsg);
  $self->{serverBots}{$srvBot}=\%srvBotInfo;
  $self->{lcServerBots}{$lcBotName}=$srvBot;
  my @legacyAddUserFields=(qw'country cpu');
  push(@legacyAddUserFields,'accountId') unless($self->{serverMode} == SRV_MODE_LAN);
  broadcastLegacy($self,['ADDUSER',$srvBot,@srvBotInfo{qw'country accountId lobbyClient'}],['ADDUSER',$srvBot,@srvBotInfo{@legacyAddUserFields}]);
  broadcast($self,'CLIENTSTATUS',$srvBot,$marshalledBotStatus) if($marshalledBotStatus);
}

sub srvBotRemove {
  my ($self,$srvBot,$reason)=@_;
  croak "invalid srvBotRemove call: unknown server bot \"$srvBot\"" unless(exists $self->{serverBots}{$srvBot});
  map {delete $self->{channelBots}{$_}{$srvBot}; broadcastChannel($self,$_,'LEFT',$_,$srvBot,defined $reason ? $reason : ())} (keys %{$self->{serverBots}{$srvBot}{channels}});
  delete $self->{serverBots}{$srvBot};
  delete $self->{lcServerBots}{lc($srvBot)};
  broadcast($self,'REMOVEUSER',$srvBot);
}

sub srvBotUpdateStatus {
  my ($self,$srvBot,$r_statusUpdates)=@_;
  croak "invalid srvBotUpdateStatus call: unknown server bot \"$srvBot\"" unless(exists $self->{serverBots}{$srvBot});
  my $r_srvBotStatus=$self->{serverBots}{$srvBot}{status};
  my $statusUpdated;
  foreach my $field (keys %{$r_statusUpdates}) {
    croak "invalid srvBotUpdateStatus call: unknown status field \"$field\"" unless(exists $r_srvBotStatus->{$field});
    next if($r_srvBotStatus->{$field} == $r_statusUpdates->{$field});
    $r_srvBotStatus->{$field}=$r_statusUpdates->{$field};
    $statusUpdated=1;
  }
  return unless($statusUpdated);
  my $marshalledStatus=marshallClientStatus($r_srvBotStatus);
  $self->{serverBots}{$srvBot}{marshalledStatus}=$marshalledStatus;
  broadcast($self,'CLIENTSTATUS',$srvBot,$marshalledStatus);
}

sub srvBotJoinChannel {
  my ($self,$srvBot,$chan,$r_onChanMsg)=@_;
  croak "invalid srvBotJoinChannel call: unknown server bot \"$srvBot\"" unless(exists $self->{serverBots}{$srvBot});
  croak "invalid srvBotJoinChannel call: server bot \"$srvBot\" is already in channel \"$chan\"" if(exists $self->{channelBots}{$chan}{$srvBot});
  $self->{channelBots}{$chan}{$srvBot}=$r_onChanMsg;
  $self->{serverBots}{$srvBot}{channels}{$chan}=1;
  broadcastChannel($self,$chan,'JOINED',$chan,$srvBot);
}

sub srvBotLeaveChannel {
  my ($self,$srvBot,$chan,$reason)=@_;
  croak "invalid srvBotLeaveChannel call: unknown server bot \"$srvBot\"" unless(exists $self->{serverBots}{$srvBot});
  croak "invalid srvBotLeaveChannel call: server bot \"$srvBot\" is not in channel \"$chan\"" unless(exists $self->{channelBots}{$chan}{$srvBot});
  delete $self->{channelBots}{$chan}{$srvBot};
  delete $self->{serverBots}{$srvBot}{channels}{$chan};
  broadcastChannel($self,$chan,'LEFT',$chan,$srvBot,defined $reason ? $reason : ());
}

sub srvBotSay {
  my ($self,$srvBot,$chan,$r_msgs,$isExMsg)=@_;
  return unless(defined $r_msgs && @{$r_msgs});
  my $r_srvBotInfo=$self->{serverBots}{$srvBot};
  return unless(defined $r_srvBotInfo && exists $r_srvBotInfo->{channels}{$chan});
  my $saidCmd=$isExMsg?'SAIDEX':'SAID';
  map {broadcastChannel($self,$chan,$saidCmd,$chan,$srvBot,$_);broadcastChannelMsgToSrvBots($self,undef,$srvBot,$r_srvBotInfo,$chan,$_,$isExMsg)} @{$r_msgs};
}

sub srvBotSayPrivate {
  my ($self,$srvBot,$userName,$r_msgs,$isExMsg)=@_;
  return unless(defined $r_msgs && @{$r_msgs});
  my $r_srvBotInfo=$self->{serverBots}{$srvBot};
  return unless(defined $r_srvBotInfo);
  my $accountId; ($accountId,$userName) = @{$userName} if(ref $userName ne '');
  my $recipient=getOnlineClientName($self,$accountId,$userName);
  if(defined $recipient) {
    my $srvBotAccountId=$r_srvBotInfo->{accountId};
    return if($srvBotAccountId && exists $self->{users}{$recipient}{ignoredAccounts}{$srvBotAccountId});
    my $saidCmd=$isExMsg?'SAIDPRIVATEEX':'SAIDPRIVATE';
    map {sendUser($self,$recipient,[$saidCmd,$srvBot,$_])} @{$r_msgs};
  }elsif(exists $self->{serverBots}{$userName}) {
    map {sendPrivateMsgToSrvBot($self,undef,$srvBot,$r_srvBotInfo,$userName,$_,$isExMsg)} @{$r_msgs};
  }
}

package SpringLobbyServer::ServerBot;

use Scalar::Util 'weaken';

sub new {
  my ($this,$springLobbyServer,$srvBot,@addBotParams)=@_;
  my $class = ref($this) || $this;
  $springLobbyServer->srvBotAdd($srvBot,@addBotParams);
  my $weakSpringLobbyServer=$springLobbyServer;
  weaken($weakSpringLobbyServer);
  my $self=[$weakSpringLobbyServer,$srvBot];
  bless($self,$class);
  return $self;
}

sub remove {
  my $self=shift;
  return unless(defined $self->[0]);
  $self->[0]->srvBotRemove($self->[1],@_);
  undef $self->[0];
}

sub updateStatus {
  my $self=shift;
  return unless(defined $self->[0]);
  $self->[0]->srvBotUpdateStatus($self->[1],@_);
}

sub joinChannel {
  my $self=shift;
  return unless(defined $self->[0]);
  $self->[0]->srvBotJoinChannel($self->[1],@_);
}

sub leaveChannel {
  my $self=shift;
  return unless(defined $self->[0]);
  $self->[0]->srvBotLeaveChannel($self->[1],@_);
}

sub say {
  my $self=shift;
  return unless(defined $self->[0]);
  $self->[0]->srvBotSay($self->[1],@_);
}

sub sayPrivate {
  my $self=shift;
  return unless(defined $self->[0]);
  $self->[0]->srvBotSayPrivate($self->[1],@_);
}

sub DESTROY {
  my $self=shift;
  return unless(defined $self->[0]);
  $self->[0]->srvBotRemove($self->[1]);
}
