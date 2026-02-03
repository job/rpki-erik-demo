package APNIC::RPKI::Erik::Client;

use warnings;
use strict;

use APNIC::RPKI::Erik::Index;
use APNIC::RPKI::Erik::Partition;
use APNIC::RPKI::Manifest;
use APNIC::RPKI::OpenSSL;

use File::Slurp qw(read_file write_file);
use LWP::UserAgent;
use MIME::Base64 qw(encode_base64url);

sub new
{
    my ($class, $dir) = @_;

    my $ua = LWP::UserAgent->new();
    my $openssl = APNIC::RPKI::OpenSSL->new();

    my $self = {
        ua      => $ua,
        dir     => $dir,
        openssl => $openssl,
    };
    bless $self, $class;
    return $self;
}

sub hash_to_url
{
    my ($hostname, $hash) = @_;

    $hash = pack('H*', $hash);
    my $hash_segment = encode_base64url($hash);
    my $url = "http://$hostname/.well-known/ni/sha-256/$hash_segment";
    return $url;
}

sub synchronise
{
    my ($self, $hostname, $fqdns) = @_;

    my $ua      = $self->{'ua'};
    my $dir     = $self->{'dir'};
    my $openssl = $self->{'openssl'};

    for my $fqdn (@{$fqdns}) {
        my $base_url = "http://$hostname/.well-known";
        my $index_url = "$base_url/erik/index/$fqdn";
        my $index_res = $ua->get($index_url);
        if (not $index_res->is_success()) {
            die "Unable to fetch index file: ".
                $index_res->status_line();
        }

        my $index_content = $index_res->decoded_content();
        my $index = APNIC::RPKI::Erik::Index->new();
        $index->decode($index_content);

        my $index_scope = $index->index_scope();
        if ($index_scope ne $fqdn) {
            die "Got incorrect index scope '$index_scope' (expected ".
                "'$fqdn')";
        }

        my @partition_list = @{$index->partition_list()};
        for my $entry (@partition_list) {
            my ($size, $hash) =
                @{$entry}{qw(size hash)};
            my $partition_url = hash_to_url($hostname, $hash);
            my $partition_res = $ua->get($partition_url);
            if (not $partition_res->is_success()) {
                die "Unable to fetch partition file: ".
                    $partition_res->status_line();
            }

            my $partition_content = $partition_res->decoded_content();
            my $partition = APNIC::RPKI::Erik::Partition->new();
            $partition->decode($partition_content);

            my @manifest_list = @{$partition->manifest_list()};
            for my $entry (@manifest_list) {
                my ($mftnum, $size, $this_update, $hash, $locations, $aki) =
                    @{$entry}{qw(manifest_number size this_update hash
                                 locations aki)};
                my @locs = sort @{$locations};
                my $location = $locs[0];
                my $uri = URI->new($location);
                my $path = $uri->path();
                $path =~ s/^\///;
                my ($pdir) = ($path =~ /^(.*)\//);
                my ($file) = ($path =~ /^.*\/(.*)$/);
                chdir $dir or die $!;
                system("mkdir -p $pdir");
                my $get = 0;
                if (-e $path) {
                    my $digest = Digest::SHA->new(256);
                    $digest->addfile($path);
                    my $content = lc $digest->hexdigest();
                    if ($content ne $hash) {
                        $get = 1;
                    }
                } else {
                    $get = 1;
                }
                if ($get) {
                    my $manifest_url = hash_to_url($hostname, $hash);
                    my $mft_res = $ua->get($manifest_url);
                    if (not $mft_res->is_success()) {
                        die "Unable to fetch manifest: ".
                            $mft_res->status_line();
                    }
                    write_file($path, $mft_res->decoded_content());

		    my $mdata = $openssl->verify_cms($path);
                    my $manifest = APNIC::RPKI::Manifest->new();
                    $manifest->decode($mdata);
                    my @files = @{$manifest->files() || []};
                    for my $file (@files) {
                        my $filename = $file->{'filename'};
                        my $hash = $file->{'hash'};
                        my $fpath = "$pdir/$filename";
                        my $get = 0;
                        if (-e $fpath) {
                            my $digest = Digest::SHA->new(256);
                            $digest->addfile($fpath);
                            my $content = lc $digest->hexdigest();
                            if ($content ne $hash) {
                                $get = 1;
                            }
                        } else {
                            $get = 1;
                        }
                        if ($get) {
                            my $o_url = hash_to_url($hostname, $hash);
                            my $res = $ua->get($o_url);
                            if (not $res->is_success()) {
                                die "Unable to fetch object: ".
                                    $res->status_line();
                            }
                            write_file($fpath, $res->decoded_content());
                        }
                    }
                }
            }
        }
    }
}

1;
