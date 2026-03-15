#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::Erik::Updater;
use APNIC::RPKI::Erik::Client;
use APNIC::RPKI::Erik::Server;

use Cwd qw(cwd);
use DateTime;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);

use Test::More tests => 10;

my $pid;

{
    my $rtd = tempdir(CLEANUP => 1);
    system("cp -r eg/repo/* $rtd/");

    my $cwd = cwd();
    my $td = tempdir(CLEANUP => 1);
    my $updater =
        APNIC::RPKI::Erik::Updater->new(
            $rtd, $td,
            write_snapshots => 1
        );
    eval {
        $updater->synchronise();
    };
    my $error = $@;
    ok((not $error),
        "Wrote Erik disk state successfully");
    diag $error if $error;

    my $server = APNIC::RPKI::Erik::Server->new(0, $td);
    my $port = $server->{'port'};
    if ($pid = fork()) {
    } else {
        $server->run();
        exit(0);
    }

    my $otd = tempdir(CLEANUP => 1);
    my $client =
        APNIC::RPKI::Erik::Client->new(
            $otd,
            use_snapshots => 1
        );
    my $res = eval {
        $client->synchronise("localhost:$port", ["rpki.roa.net"]);
    };
    $error = $@;
    ok((not $error),
        "Synchronised remote content successfully");
    diag $error if $error;
    is($res->{'local_file_count'},
       $res->{'local_file_reliance'},
       "Each file from snapshot was used");

    my $diff = sub {
        my @res =
            grep { !/local-erik-relay/ }
                `diff -r $rtd $otd`;
        @res
    };

    chdir $cwd or die $!;
    my @differences = $diff->();
    ok((not @differences), "Synchronisation result matches original");
    if (@differences) {
        diag "Server directory: $rtd";
        diag "Client directory: $otd";
        diag @differences;
    }

    system("cp -r eg/repo2/61 $rtd/rpki.roa.net/rrdp/xTom/");
    eval {
        $updater->synchronise();
    };
    $error = $@;
    ok((not $error),
        "Updated Erik disk state successfully");
    diag $error if $error;

    eval {
        $client->synchronise("localhost:$port", ["rpki.roa.net"]);
    };
    $error = $@;
    ok((not $error),
        "Resynchronised remote content successfully");
    diag $error if $error;
    
    @differences = $diff->();
    ok((not @differences), "Resynchronisation result matches original");
    if (@differences) {
        diag "Server directory: $rtd";
        diag "Client directory: $otd";
        diag @differences;
    }

    system("rm -rf $rtd/rpki.roa.net/rrdp/xTom/61");
    eval {
        $updater->synchronise();
    };
    $error = $@;
    ok((not $error),
        "Updated Erik disk state successfully");
    diag $error if $error;

    eval {
        $client->synchronise("localhost:$port", ["rpki.roa.net"]);
    };
    $error = $@;
    ok((not $error),
        "Resynchronised remote content successfully");
    diag $error if $error;
    
    @differences = $diff->();
    ok((not @differences), "Resynchronisation result matches original");
    if (@differences) {
        diag "Server directory: $rtd";
        diag "Client directory: $otd";
        diag @differences;
    }
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
