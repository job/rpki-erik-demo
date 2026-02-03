#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::Erik::Client;

use DateTime;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);

use Test::More tests => 1;

ok(1);

sub test
{
    my $td = tempdir(CLEANUP => 1);
    my $client = APNIC::RPKI::Erik::Client->new($td);
    $client->synchronise("miso.sobornost.net",
                         ["rpki.roa.net"]);

    system("tree $td");
}

1;
