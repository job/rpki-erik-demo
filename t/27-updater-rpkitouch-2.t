#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::Erik::Updater;
use APNIC::RPKI::Erik::Client;
use APNIC::RPKI::Erik::Server;
use APNIC::RPKI::Erik::Index;
use APNIC::RPKI::Erik::Partition;
use APNIC::RPKI::OpenSSL;

use Cwd qw(cwd);
use DateTime;
use MIME::Base64 qw(encode_base64url);
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use List::Util qw(first);

use Test::More tests => 8;

{
    my $fqdn = "rpkica.twnic.tw";

    my $cwd = cwd();
    my $td = tempdir(CLEANUP => 1);
    my $updater = APNIC::RPKI::Erik::Updater->new("eg/twnic-repo", $td);
    eval {
        $updater->synchronise();
    };
    my $error = $@;
    ok((not $error),
        "Wrote Erik disk state successfully");
    diag $error if $error;

    my $eft = File::Temp->new();
    my $efn = $eft->filename();
    $eft->flush();

    my $tail_err = ($ENV{'APNIC_DEBUG'}) ? "" : " 2>/dev/null";
    my $tail_bth = ($ENV{'APNIC_DEBUG'}) ? "" : " >/dev/null 2>&1";

    my $ft = File::Temp->new();
    my $fn = $ft->filename();
    my $res = system("rpkitouch -c eg/rpki-client.ccr | grep rpkica.twnic.tw > $fn $tail_err");
    if ($res != 0) {
        die "rpkitouch command failed";
    }

    my $oft = File::Temp->new();
    my $ofn = $oft->filename();
    $res = system("comm -1 -3 $efn $fn | awk '{ print \$NF }' > $ofn $tail_err");
    if ($res != 0) {
        die "File generation command failed";
    }

    my $rt_od = tempdir(UNLINK => 1);
    chdir("eg/twnic-repo") or die $!;
    $res = system("sort -R $ofn | xargs rpkitouch -p | xargs rpkitouch -v -d $rt_od $tail_bth");
    if ($res != 0) {
        die "rpkitouch (2) command failed";
    }

    chdir("$cwd/eg") or die $!;
    $res = system("rpkitouch -C -v -d $rt_od rpki-client.ccr $tail_bth");
    if ($res != 0) {
        die "rpkitouch (3) command failed";
    }

    ok(1, "Wrote Erik disk state (rpkitouch) successfully");

    sub load_index
    {
        my ($path) = @_;
        my $data = read_file($path);
        my $index = APNIC::RPKI::Erik::Index->new();
        $index->decode($data);
        return $index;
    }

    sub load_partition
    {
        my ($path) = @_;
        my $data = read_file($path);
        my $index = APNIC::RPKI::Erik::Partition->new();
        $index->decode($data);
        return $index;
    }

    my $red_index = load_index("$td/.well-known/erik/index/$fqdn");
    my $rt_index  = load_index("$rt_od/erik/index/$fqdn");

    sub convert_hash
    {
        my ($hash) = @_;
        $hash = pack('H*', $hash);
        return encode_base64url($hash);
    }

    my %red_partitions;
    my %rt_partitions;

    for my $red_partition_rec (@{$red_index->partition_list()}) {
        my $hash = $red_partition_rec->{'hash'};
        my $hash_seg = convert_hash($hash);
        my $path = "$td/.well-known/ni/sha-256/$hash_seg"; 
        my $partition = load_partition($path);
        $red_partitions{$hash} = $partition;
    }

    for my $rt_partition_rec (@{$rt_index->partition_list()}) {
        my $hash = $rt_partition_rec->{'hash'};
        my $hash_seg = convert_hash($hash);
        my ($f, $s) = ($hash_seg =~ /.*(..)(..)$/);
        my $path = "$rt_od/static/$f/$s/$hash_seg";
        my $partition = load_partition($path);
        $rt_partitions{$hash} = $partition;
    }

    my $red_partition_count = scalar @{$red_index->partition_list()}; 
    my $rt_partition_count  = scalar @{$rt_index->partition_list()};
    is($red_partition_count, $rt_partition_count,
        "Got same number of partitions in each index");

    my @red_not_in_rt;
    for my $red_hash (keys %red_partitions) {
        my $red_partition = $red_partitions{$red_hash};
        my $rt_partition  = $rt_partitions{$red_hash};
        if (not $rt_partition) {
            for my $manifest_rec (@{$red_partition->manifest_list()}) {
                my $location = $manifest_rec->{'locations'}->[0];
                $location =~ s/rsync:..//;
                my $mft_cms = read_file("$cwd/eg/twnic-repo/$location");
                my $cms = APNIC::RPKI::CMS->new();
                $cms->decode($mft_cms);
		my $manifest = APNIC::RPKI::Manifest->new();
		$manifest->decode($cms->payload()->{'content'}->{'encapContentInfo'}->{'eContent'});
		my $ee_cert = $cms->payload()->{'content'}->{'certificates'}->[0];
		my $x509 = APNIC::RPKI::X509->new();
		$x509->decode($ee_cert);
		my $aki_raw_obj =
		    first { $_->{'extnID'} eq '2.5.29.35' }
			@{$x509->payload()->{'tbsCertificate'}->{'extensions'}};
		my $aki_raw = $aki_raw_obj->{'extnValue'};
		my $aki = lc(unpack('H*', $aki_raw));
		$aki =~ s/^........//;
		$aki = lc $aki; 
		my $digest_data = sha256($mft_cms);
		my $digest_base64 = encode_base64url($digest_data);
                diag "$red_hash: manifest in rpkitouch partition AKI: $digest_base64";
            }
            push @red_not_in_rt, $red_hash;
        }
    }
    is((scalar @red_not_in_rt), 0,
        'All rpki-erik-demo partitions are in rpkitouch index');

    my @rt_not_in_red;
    for my $rt_hash (keys %rt_partitions) {
        my $rt_partition = $rt_partitions{$rt_hash};
        my $red_partition  = $red_partitions{$rt_hash};
        if (not $red_partition) {
            for my $manifest_rec (@{$rt_partition->manifest_list()}) {
                my $location = $manifest_rec->{'locations'}->[0];
                $location =~ s/rsync:..//;
                my $mft_cms = read_file("$cwd/eg/twnic-repo/$location");
                my $cms = APNIC::RPKI::CMS->new();
                $cms->decode($mft_cms);
		my $manifest = APNIC::RPKI::Manifest->new();
		$manifest->decode($cms->payload()->{'content'}->{'encapContentInfo'}->{'eContent'});
		my $ee_cert = $cms->payload()->{'content'}->{'certificates'}->[0];
		my $x509 = APNIC::RPKI::X509->new();
		$x509->decode($ee_cert);
		my $aki_raw_obj =
		    first { $_->{'extnID'} eq '2.5.29.35' }
			@{$x509->payload()->{'tbsCertificate'}->{'extensions'}};
		my $aki_raw = $aki_raw_obj->{'extnValue'};
		my $aki = lc(unpack('H*', $aki_raw));
		$aki =~ s/^........//;
		$aki = lc $aki; 
		my $digest_data = sha256($mft_cms);
		my $digest_base64 = encode_base64url($digest_data);
                diag "$rt_hash: manifest in rpkitouch partition AKI: $digest_base64";
            }
            push @rt_not_in_red, $rt_hash;
        }
    }
    is((scalar @rt_not_in_red), 0,
        'All rpkitouch partitions are in rpki-erik-demo index');

    for my $ml (map { @{$_->manifest_list()} } (values %red_partitions,
                                                values %rt_partitions)) {
        $ml->{'this_update'} = $ml->{'this_update'}->strftime('%F %T');
    }

    my @red_manifests = map { @{$_->manifest_list()} } values %red_partitions;
    my @rt_manifests  = map { @{$_->manifest_list()} } values %rt_partitions;

    @red_manifests = sort { $a->{'hash'} cmp $b->{'hash'} } @red_manifests;
    @rt_manifests  = sort { $a->{'hash'} cmp $b->{'hash'} } @rt_manifests;
    
    $res = is_deeply(\@rt_manifests, \@red_manifests,
        "Manifest generation produced same results");

    my %red_manifest_lookup =
        map { $_->{'hash'} => $_ }
            @red_manifests;
    my %rt_manifest_lookup =
        map { $_->{'hash'} => $_ }
            @rt_manifests;

    my @red_not_in_rt_manifest;
    for my $red_hash (keys %red_manifest_lookup) {
        my $red_manifest = $red_manifest_lookup{$red_hash};
        my $rt_manifest  = $rt_manifest_lookup{$red_hash};
        if (not $rt_manifest) {
            push @red_not_in_rt_manifest, $red_hash;
        }
    }
    $res = is((scalar @red_not_in_rt_manifest), 0,
        'All rpki-erik-demo manifests are in rpkitouch index');
    if (not $res) {
        HASH: for my $hash (sort @red_not_in_rt_manifest) {
            my $red_manifest = $red_manifest_lookup{$hash};
            my $red_location = $red_manifest->{'locations'}->[0];
            for my $rt_manifest (@rt_manifests) {
                my $rt_location = $rt_manifest->{'locations'}->[0];
                if ($red_location eq $rt_location) {
                    use Data::Dumper;
                    diag Dumper(["rpki-erik-demo manifest", $red_manifest,
                                 "rpkitouch manifest", $rt_manifest]);
                    next HASH;
                }
            }
            diag "Did not find corresponding rpkitouch manifest for '$red_location'";
        }
    }

    my @rt_not_in_red_manifest;
    for my $rt_hash (keys %rt_manifest_lookup) {
        my $rt_manifest = $rt_manifest_lookup{$rt_hash};
        my $red_manifest  = $red_manifest_lookup{$rt_hash};
        if (not $red_manifest) {
            push @rt_not_in_red, $rt_hash;
        }
    }
    is((scalar @rt_not_in_red_manifest), 0,
        'All rpkitouch manifests are in rpki-erik-demo index');
}

1;
