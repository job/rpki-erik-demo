#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::Erik::Partition;

use DateTime;
use File::Slurp qw(read_file write_file);
use MIME::Base64 qw(decode_base64 encode_base64url);
use Digest::SHA qw(sha256);

use Test::More tests => 7;

my $path = "eg/AZmwyRKvBFv4DPl2g5IAhM8BbDvVWzZvgBLjORCoXqM.b64"; 

{
    my $data_encoded = read_file($path);    
    my $data = decode_base64($data_encoded);
    my $partition = APNIC::RPKI::Erik::Partition->new();
    my $res = $partition->decode($data);
    ok($res, "Decoded test partition successfully");

    my $partition_time = $partition->partition_time();
    is($partition_time->ymd(), "2026-01-08",
        "Decoded partition time successfully");
    my @manifest_list = @{$partition->manifest_list()};
    my $count = scalar @manifest_list;
    is($count, 59, "Decoded manifest list successfully");
}

{
    my $partition = APNIC::RPKI::Erik::Partition->new();
    $partition->partition_time(DateTime->now());
    my @manifest_list = (
        { hash            => "ABCD",
          size            => 10,
          aki             => "ABCD",
          manifest_number => 20,
          this_update     => DateTime->now(),
          locations       => [ "qwer" ] },
        { hash            => "ABCD",
          size            => 10,
          aki             => "ABCD",
          manifest_number => 20,
          this_update     => DateTime->now(),
          locations       => [ "qwer" ] },
    );
    $partition->manifest_list(\@manifest_list);
    my $enc_data = $partition->encode();
    ok($enc_data, "Encoded partition successfully");

    my $partition2 = APNIC::RPKI::Erik::Partition->new();
    my $res = $partition2->decode($enc_data);
    ok($res, "Decoded new partition successfully");
    @manifest_list = @{$partition2->manifest_list()};
    my $count = scalar @manifest_list;
    is($count, 2, "Decoded manifest list successfully");
}

{
    my $data_encoded = read_file($path);    
    my $data = decode_base64($data_encoded);
    my $digest_data = sha256($data);
    my $digest_base64 = encode_base64url($digest_data);
    $path =~ s/^...//;
    $path =~ s/.b64$//;
    is($path, $digest_base64,
        "Example file has correct filename");
}

1;
