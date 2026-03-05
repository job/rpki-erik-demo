package APNIC::RPKI::Erik::Client;

use warnings;
use strict;

use APNIC::RPKI::Erik::Index;
use APNIC::RPKI::Erik::Partition;
use APNIC::RPKI::Manifest;
use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::Utils qw(dprint);

use Cwd qw(cwd);
use Data::Dumper;
use Digest::SHA;
use File::Slurp qw(read_file write_file);
use HTTP::Async;
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
use JSON::XS qw(encode_json decode_json);
use LWP::UserAgent;
use MIME::Base64 qw(encode_base64url);

sub new
{
    my ($class, $dir, %args) = @_;

    my $ua = LWP::UserAgent->new();
    my $openssl = APNIC::RPKI::OpenSSL->new();

    my $self = {
        ua      => $ua,
        dir     => $dir,
        openssl => $openssl,
        %args
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

sub hash_to_local_path
{
    my ($ler, $hash) = @_;

    $hash = pack('H*', $hash);
    my $hash_segment = encode_base64url($hash);
    my $path = "$ler/$hash_segment";
    return $path;
}

sub synchronise
{
    my ($self, $hostname, $fqdns) = @_;

    my $ok = 1;

    my $ua      = $self->{'ua'};
    my $dir     = $self->{'dir'};
    my $openssl = $self->{'openssl'};

    my $cwd = cwd();

    my $async = HTTP::Async->new();
    my %id_to_rmd;
    my %relevant_files;
    my %fqdn_to_pt_to_mft_to_file;
    my %fqdn_to_ler;
    my @local_responses;
    my $lid = 1;

    my $ler_file_count;
    my $ler_file_reliance;

    my $ler = "$dir/local-erik-relay";
    if ($self->{"use_snapshots"}) {
        mkdir $ler;
    }

    for my $fqdn (@{$fqdns}) {
        dprint("Requesting index for '$fqdn'");
        my $mp = "$dir/${fqdn}-metadata";
        my $used_snapshot = 0;
        if (-e $mp) {
            my $content = read_file($mp);
            my $data = decode_json($content);
            $fqdn_to_pt_to_mft_to_file{$fqdn} = $data;
        } else {
            $fqdn_to_pt_to_mft_to_file{$fqdn} = {};
            if ($self->{'use_snapshots'}) {
                my $base_url = "http://$hostname/.well-known";
                my $snapshot_url = "$base_url/erik/snapshot/$fqdn";
                dprint("Submitting fetch for '$snapshot_url'");
                my $id = $async->add(HTTP::Request->new(GET => $snapshot_url));
                $id_to_rmd{$id} = {
                    type  => 'snapshot',
                    value => $fqdn
                };
                $used_snapshot = 1;
            }
        }
        if (not $used_snapshot) {
            my $base_url = "http://$hostname/.well-known";
            my $index_url = "$base_url/erik/index/$fqdn";
            dprint("Submitting fetch for '$index_url'");
            my $id = $async->add(HTTP::Request->new(GET => $index_url));
            $id_to_rmd{$id} = {
                type  => 'fqdn',
                value => $fqdn
            };
        }
    }

    my ($res, $id);
    while (($res, $id) = $async->wait_for_next_response()
            or (@local_responses and ($res, $id) = @{shift @local_responses})) {
        my $rmd = $id_to_rmd{$id};
        my $index_url = $res->request()->uri();
        my ($type, $value) = @{$rmd}{qw(type value)};
        if ($type eq 'snapshot') {
            my $fqdn = $value;
            if (not $res->is_success()) {
                dprint("Unable to fetch snapshot for '$fqdn': ".Dumper($res));
            } else {
                $fqdn_to_ler{$fqdn} = 1;
                eval {
                    my $ft = File::Temp->new();
                    my $fn = $ft->filename();
                    write_file($fn, $res->content());
                    $ft->flush();
                    my $res = system("mv $fn $fn.gz");
                    if ($res != 0) {
                        die "unable to move file";
                    }
                    $res = system("gunzip $fn.gz");
                    if ($res != 0) {
                        die "unable to gunzip file";
                    }
                    my $content = read_file($fn);
                    
                    while ($content) {
                        my $rfb = substr($content, 0, 1);
                        my $fb = unpack('C', $rfb);
                        if ($fb != 0x30) {
                            die "Expected 0x30 for start of object";
                        }
                        my $tlb = substr($content, 1, 1);
                        my $lb = unpack('C', $tlb);
                        my $new_object;
                        if ($lb <= 127) {
                            dprint("Got short object in snapshot ($lb bytes)");
                            $new_object = $rfb.$tlb.substr($content, 2, $lb);
                            $content = substr($content, 2 + $lb);
                        } else {
                            my $elb = $lb & 127;
                            dprint("Got object in snapshot ($elb extra ".
                                   "length bytes)");
                            my $raw_rlb = substr($content, 2, $elb);
                            my @rlb = unpack('C*', $raw_rlb);
                            @rlb = reverse @rlb;
                            my $new_length = 0;
                            for (my $i = 0; $i < @rlb; $i++) {
                                my $inc = ($rlb[$i] * (256 ** $i));
                                dprint("Byte $i: ".$rlb[$i]);
                                dprint("Increment $i: $inc");
                                $new_length += $inc;
                            }
                            dprint("Got object in snapshot ($new_length ".
                                   "bytes)");
                            $new_object = $rfb.$tlb.$raw_rlb.substr($content, 2 + $elb, $new_length);
                            $content = substr($content, 2 + $elb + $new_length);
                        }

			my $digest = Digest::SHA->new(256);
			$digest->add($new_object);
			my $digest_data = $digest->clone()->digest();
			my $path_segment = encode_base64url($digest_data);
                        write_file("$ler/$path_segment", $new_object);
                        dprint("Wrote object to local relay ($path_segment)");
                        $ler_file_count++;
                    }
                };
                if (my $error = $@) {
                    die "Unable to process snapshot for '$fqdn': $error";
                }
            }
            my $base_url = "http://$hostname/.well-known";
            my $index_url = "$base_url/erik/index/$fqdn";
            dprint("Submitting fetch for '$index_url'");
            my $id = $async->add(HTTP::Request->new(GET => $index_url));
            $id_to_rmd{$id} = {
                type  => 'fqdn',
                value => $fqdn
            };
        } elsif ($type eq 'fqdn') {
            my $fqdn = $value;
            my $pt_to_mft_to_file = $fqdn_to_pt_to_mft_to_file{$fqdn};
            if (not $res->is_success()) {
                dprint("Unable to fetch index for '$fqdn': ".Dumper($res));
                $ok = 0;
            } else {
                dprint("Fetched index '$index_url'");

                my $index_content = $res->decoded_content();
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
                    my $pt = "$hash-$size";
                    if ($pt_to_mft_to_file->{$pt}) {
                        dprint("Do not need to fetch partition ".
                               "($hash, $size)");
                        for my $mft (keys %{$pt_to_mft_to_file->{$pt}}) {
                            for my $file (@{$pt_to_mft_to_file->{$pt}->{$mft}}) {
                                $relevant_files{$file} = 1;
                            }
                        }
                    } else {
                        dprint("Processing partition '$hash' with size '$size'");
                        my $partition_url = hash_to_url($hostname, $hash);
                        dprint("Submitting fetch for partition '$partition_url'");
                        my $mft_to_file = {};
                        $pt_to_mft_to_file->{$pt} = $mft_to_file;

                        my $id = $async->add(HTTP::Request->new(GET => $partition_url));
                        $id_to_rmd{$id} = {
                            type  => 'partition',
                            value => [$fqdn, $hash, $size,
                                      $mft_to_file]
                        };
                    }
                }
            }
        } elsif ($type eq 'partition') {
            my ($fqdn, $hash, $size, $mft_to_file) = @{$value};
            my $partition_url = $res->request()->uri();
            if (not $res->is_success()) {
                dprint("Unable to fetch partition for '$fqdn' ('$hash'): ".
                       Dumper($res));
                $ok = 0;
            } else {
                dprint("Fetched partition '$partition_url'");

                my $partition_content = $res->content();
                my $partition = APNIC::RPKI::Erik::Partition->new();
                $partition->decode($partition_content);
                dprint("Decoded partition '$partition_url'");

                my @manifest_list = @{$partition->manifest_list()};
                for my $entry (@manifest_list) {
                    my ($mftnum, $size, $this_update, $hash, $locations, $aki) =
                        @{$entry}{qw(manifest_number size this_update hash
                                    locations aki)};
                    my @locs = sort @{$locations};
                    my $location = $locs[0];
                    my @mft_files;
                    $mft_to_file->{$location} = \@mft_files;
                    dprint("Processing manifest '$location' (number ".
                        "'$mftnum', size '$size')");
                    my $uri = URI->new($location);
                    my $path = $uri->path();
                    $path =~ s/^\///;
                    $path = $uri->host()."/$path";
                    $relevant_files{$path} = 1;
                    push @mft_files, $path;
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
                        my $handled = 0;
                        dprint("Need to fetch manifest '$location'");
                        my $o_path = hash_to_local_path($ler, $hash);
                        if (-e $o_path) {
                            $ler_file_reliance++;
                            dprint("Found '$location' locally");
                            my $req = HTTP::Request->new();
                            $req->uri(URI->new("file://$o_path"));
                            my $res = HTTP::Response->new();
                            $res->request($req);
                            $res->code(200);
                            my $data = read_file($o_path);
                            $res->content($data);
                            $lid++;
                            my $llid = "lid_$lid";
                            $id_to_rmd{$llid} = {
                                type  => 'manifest',
                                value => [$fqdn, $entry, $path, $pdir, \@mft_files]
                            };
                            push @local_responses, [$res, $llid];
                            $handled = 1;
                        }
                        if (not $handled and $fqdn_to_ler{$fqdn}) {
                            dprint("Did not find '$location' locally");
                        }
                        if (not $handled) {
                            my $manifest_url = hash_to_url($hostname, $hash);
                            dprint("Submitting fetch for manifest '$manifest_url'");

                            my $id = $async->add(HTTP::Request->new(GET => $manifest_url));
                            $id_to_rmd{$id} = {
                                type  => 'manifest',
                                value => [$fqdn, $entry, $path, $pdir, \@mft_files]
                            };
                        }
                    } else {
                        dprint("Do not need to fetch manifest '$location'");

                        my $mdata = $openssl->verify_cms($path);
                        my $manifest = APNIC::RPKI::Manifest->new();
                        $manifest->decode($mdata);
                        my @files = @{$manifest->files() || []};
                        my $file_count = scalar @files;
                        for my $file (@files) {
                            my $filename = $file->{'filename'};
                            my $hash = $file->{'hash'};
                            my $fpath = "$pdir/$filename";
                            $relevant_files{$fpath} = 1;
                        }
                    }
                }
            }
        } elsif ($type eq 'manifest') {
            my ($fqdn, $entry, $path, $pdir, $mft_files) = @{$value};
            my $manifest_url = $res->request()->uri();
            if (not $res->is_success()) {
                dprint("Unable to fetch manifest for '$path': ".
                       Dumper($res));
                $ok = 0;
            } else {
                write_file($path, $res->decoded_content());
                dprint("Fetched manifest '$manifest_url'");
                dprint("Wrote manifest to path '$path'");

                my $mdata = $openssl->verify_cms($path);
                my $manifest = APNIC::RPKI::Manifest->new();
                $manifest->decode($mdata);
                my @files = @{$manifest->files() || []};
                my $file_count = scalar @files;
                dprint("Manifest file count: '$file_count'");
                for my $file (@files) {
                    my $filename = $file->{'filename'};
                    dprint("Processing file '$filename'");
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
                    $relevant_files{$fpath} = 1;
                    push @{$mft_files}, $fpath;
                    if ($get) {
                        my $handled = 0;
                        my $o_path = hash_to_local_path($ler, $hash);
                        if (-e $o_path) {
                            $ler_file_reliance++;
                            dprint("Found '$filename' locally");
                            my $req = HTTP::Request->new();
                            $req->uri(URI->new("file://$o_path"));
                            my $res = HTTP::Response->new();
                            $res->request($req);
                            $res->code(200);
                            my $data = read_file($o_path);
                            $res->content($data);
                            $lid++;
                            my $llid = "lid_$lid";
                            $id_to_rmd{$llid} = {
                                type  => 'object',
                                value => [$fqdn, $fpath]
                            };
                            push @local_responses, [$res, $llid];
                            $handled = 1;
                        }
                        if (not $handled and $fqdn_to_ler{$fqdn}) {
                            dprint("Did not find '$filename' locally");
                        }
                        if (not $handled) {
                            my $o_url = hash_to_url($hostname, $hash);
                            dprint("Submitting fetch for file '$o_url'");

                            my $id = $async->add(HTTP::Request->new(GET => $o_url));
                            $id_to_rmd{$id} = {
                                type  => 'object',
                                value => [$fqdn, $fpath]
                            };
                        }
                    } else {
                        dprint("Do not need to fetch file '$file'");
                    }
                }
            }
        } elsif ($type eq 'object') {
            my ($fqdn, $fpath) = @{$value};
            my $object_url = $res->request()->uri();
            if (not $res->is_success()) {
                dprint("Unable to fetch object for '$fpath': ".
                       Dumper($res));
                $ok = 0;
            } else {
                write_file($fpath, $res->decoded_content());
                dprint("Fetched file '$object_url'");
                dprint("Wrote file to path '$fpath'");
            }
        }
    }

    if (not $ok) {
        return;
    }

    for my $fqdn (@{$fqdns}) {
	chdir $dir or die $!;
	my @files = `find $fqdn -type f`;
	for my $file (@files) {
	    chomp $file;
	    $file =~ s/^\.\///;
	    if (not $relevant_files{$file}) {
		dprint("Removing '$file' (deleted)");
		unlink $file or die $!;
	    }
	}

	my @empty_dirs = `find $fqdn -type d -empty`;
	for my $empty_dir (@empty_dirs) {
	    chomp $empty_dir;
            dprint("Removing '$empty_dir' (empty directory)");
            rmdir $empty_dir or die $!;
	}

        my $mp = "$dir/${fqdn}-metadata";
        my $metadata = encode_json($fqdn_to_pt_to_mft_to_file{$fqdn});
        write_file($mp, $metadata);
    }

    chdir $cwd;

    return { local_file_count    => $ler_file_count,
             local_file_reliance => $ler_file_reliance };
}

1;
