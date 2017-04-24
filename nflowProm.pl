#!/usr/bin/perl
#
# nfdump parser to prometheus pushgateway
#
#
use warnings;
use strict;
use feature ':5.10';
use Math::Round;
use POSIX qw(strftime);
use Mojo::DOM;
use Mojo::UserAgent;

my $flow_dir = '/opt/nfsen/profiles-data/live';
my $acct_dir  = '/opt/scripts/asn-accounting';
my $nfdump   = 'nfdump';
my $asn_names = '/opt/scripts/asn-accounting/autnums.html';
my $url = 'http://prompushgateway:9091/metrics/job/netflow';

# list of routers to gather ASN based netflow v9 (nextas and prevas) from
my $nodes = "routerABC:router123";

######
# source for ASN names: http://www.cidr-report.org/as2.0/autnums.html
# nfdump file names: /opt/nfsen/profiles-data/live/router123/nfcapd.201704131910

my $date = strftime '%Y%m%d', localtime();
my $hour = strftime '%H', localtime();
my $min  = strftime '%M', localtime();

my $mins = 60 * $hour + $min;
my $newmins = nearest (5, ($mins -= 10));
my $newtime = sprintf "%02d%02d", $newmins / 60, $newmins % 60;

my %traffic;

my @nfdump_down = qx($nfdump -M $flow_dir/$nodes -R nfcapd.$date$newtime -O bps -A prevas -o "fmt:%pas:%bps");
for my $line (@nfdump_down) {
	my ( $asn, $rate ) = ($1, $2) if $line =~ /\s+(\d+):\s+(\d+\.?\d?\s?[MG]?)\s+$/;
	if ( $asn ) {
		if ( $rate !~ /(M|G)/ ) {
			$rate = ( $rate / 1000000 ); 	
		} else {
			$rate =~ s/\s+M//;
		}
		$traffic{"$asn"}->{'down'} = $rate;
	}
}

my @nfdump_up = qx($nfdump -M $flow_dir/$nodes -R nfcapd.$date$newtime -O bps -A nextas -o "fmt:%nas:%bps");
for my $line (@nfdump_up) {
	my ( $asn, $rate ) = ($1, $2) if $line =~ /\s+([0-9]+):\s+(\d+\.?\d?\s?[MG]?)\s+$/;
	if ( $asn ) {
		if ( $rate !~ /(M|G)/ ) {
			$rate = ( $rate / 1000000 ); 	
		} else {
			$rate =~ s/\s+M//;
		}
		$traffic{"$asn"}->{'up'} = $rate;
	}
}

open (my $ASNAMES, '<', $asn_names) or die "Could not open file '$asn_names' $!";
while (<$ASNAMES>) {
	# <a href="/cgi-bin/as-report?as=AS395666&view=2.0">AS395666</a> GSS-MICHIGAN - Guardian Alarm Co of Michigan Inc., US
	if ( /<.*?>\s*AS(.*?)\s*<\/a>\s*(.*?)\n/ ) {
		my ( $asn, $name ) = ($1, $2);
		if ($traffic{"$asn"}) {
			$traffic{"$asn"}->{'name'} = $name;
		}
	}
}
close $ASNAMES;

my $data;
for my $asn ( keys %traffic ) {
	$data .= qq(bits_down{asn="$asn", name="$traffic{$asn}->{'name'}"} );
	$data .= ($traffic{$asn}{down} || "0") . "\n";
	$data .= qq(bits_up{asn="$asn", name="$traffic{$asn}->{'name'}"} );
	$data .= ($traffic{$asn}{up} || "0") . "\n";
}

my $ua = new Mojo::UserAgent->new;
my $tx = $ua->post($url, {'Content-Type' => 'application/octet-stream'}, $data);

if (my $res = $tx->result) {

	if ( $res->is_success ) {
#		say $res->code;
#		say $res->message;
	}
	elsif ( $res->is_error ) {
		say $res->code;
		say $res->message;
	}

}

