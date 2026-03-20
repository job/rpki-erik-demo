package APNIC::RPKI::Erik::Client;

use warnings;
use strict;

use APNIC::RPKI::Erik::Index;
use APNIC::RPKI::Erik::Partition;
use APNIC::RPKI::Erik::Updater;
use APNIC::RPKI::Manifest;
use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::Utils qw(dprint);
use APNIC::RPKI::CMS;

use Convert::ASN1 qw(asn_read);
use Cwd qw(cwd);
use Data::Dumper;
use Digest::SHA;
use File::Path qw(mkpath);
use File::Slurp qw(read_file write_file);
use File::Temp qw(tempdir);
use IO::Async::Loop;
use IO::Async::Timer::Periodic;
use Net::Async::HTTP;
use IO::Uncompress::Gunzip qw($GunzipError);
use JSON::XS qw(encode_json decode_json);
use LWP::UserAgent;
use MIME::Base64 qw(encode_base64url);
use Class::Unload;
Class::Unload->unload('Future::XS');

$| = 1;

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
    my ($url_prefix, $hash) = @_;

    $hash = pack('H*', $hash);
    my $hash_segment = encode_base64url($hash);
    my $url = "$url_prefix/.well-known/ni/sha-256/$hash_segment";
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

    my $host = $hostname;
    my $port = 80;
    my $scheme = "http";
    if ($host =~ /:(\d+)$/) {
        $port = $1;
        $host =~ s/:\d+$//;
        if ($port == 443) {
            $scheme = "https";
        }
    }
    my $url_prefix = "$scheme://$host:$port";
    my $procs = $self->{'procs'} || 16;
    my $snapshot_procs = $self->{'snapshot_procs'} || 1;
    my $adaptive_procs = $self->{'adaptive'};
    my $adaptive_mult = 1;
    my $snapshots_only = $self->{'snapshots_only'} || 0;

    my $ok = 1;

    my $ua      = $self->{'ua'};
    my $dir     = $self->{'dir'};
    my $openssl = $self->{'openssl'};
    my $out_dir = $self->{'out_dir'} || $dir;
    my $gc      = ($self->{'out_dir'} or $self->{'no_gc'}) ? 0 : 1;

    my $cwd = cwd();

    my $loop = IO::Async::Loop->new();
    my $http = Net::Async::HTTP->new(
        fail_on_error            => 0,
        max_connections_per_host => $procs,
        max_in_flight            => $procs,
        timeout                  => 60,
        stall_timeout            => 15,
    );
    $loop->add($http);

    my %id_to_rmd;
    my %relevant_files;
    my %fqdn_to_pt_to_mft_to_file;
    my %fqdn_to_ler;
    my @local_responses;
    my $local_id = 1;
    my @remote_responses;
    my $remote_id = 1;

    my $partition_data_path = $self->{'partition_data_path'};
    if ($partition_data_path) {
        my $pd_json = read_file($partition_data_path);
        my $pd = decode_json($pd_json);
        %fqdn_to_pt_to_mft_to_file = %{$pd};
    }

    my $ler_file_count = 0;
    my $ler_file_reliance = 0;

    my $ler = "$dir/local-erik-relay";
    my $use_snapshots = $self->{"use_snapshots"};
    my $use_ttqs      = $self->{"use_ttqs"};
    if ($use_snapshots or $use_ttqs) {
        mkdir $ler;
    }
    my $queued = 0;
    my $sent = 0;
    my $received = 0;
    my $snapshots_done = 1;
    my $snapshot_count = 0;
    my $queue_size = 4;
    my @pending_requests;

    my $add_http_request = sub {
    };

    for my $fqdn (@{$fqdns}) {
        dprint("Requesting index for '$fqdn'");
        my $previously_synced = 0;
        if (-e "$dir/$fqdn") {
            $previously_synced = 1;
        }
        my $used_prefetch = 0;
        if ($previously_synced and not $use_snapshots) {
            if ($use_ttqs) {
                my $now = time();
                my $last_run = (stat("$dir/$fqdn"))[9];
                my $diff = $now - $last_run;
                my $ttq_filename;
                if ($diff <= 600) {
                    if ($diff >= 300) {
                        $ttq_filename = "10min";
                    } else {
                        $ttq_filename = "5min";
                    }
                    my $base_url = "$url_prefix/.well-known";
                    my $ttq_url = "$base_url/erik/tail/$fqdn/$ttq_filename";
                    dprint("Submitting fetch for '$ttq_url'");
                    $remote_id++;
                    my $remote_id_key = "remote_id_$remote_id";
                    push(@pending_requests, [$ttq_url, $remote_id_key, time()]);
                    $queued++;
                    $id_to_rmd{$remote_id_key} = {
                        type  => 'prefetch',
                        value => $fqdn
                    };
                    $used_prefetch = 1;
                    dprint("Submitted fetch for '$ttq_url'");
                }
            } else {
                if ($fqdn_to_pt_to_mft_to_file{$fqdn}) {
                    dprint("Using provided partition data for '$fqdn'");
                } else {
                    dprint("Generating partition data for '$fqdn' for synchronising");
                    my $cache_dir = $dir;
                    my $httpd_dir = tempdir();
                    my $updater =
                        APNIC::RPKI::Erik::Updater->new(
                            $cache_dir, $httpd_dir
                        );
                    my ($fpmf, undef) = $updater->synchronise($fqdn);
                    $fqdn_to_pt_to_mft_to_file{$fqdn} = $fpmf;
                    dprint("Generated partition data for '$fqdn' for synchronising");
                }
            }
        } else {
            if (not $fqdn_to_pt_to_mft_to_file{$fqdn}) {
                $fqdn_to_pt_to_mft_to_file{$fqdn} = {};
            }
            if ($use_snapshots) {
                my $base_url = "$url_prefix/.well-known";
                my $snapshot_url = "$base_url/erik/snapshot/$fqdn";
                dprint("Submitting fetch for '$snapshot_url'");
                $remote_id++;
                my $remote_id_key = "remote_id_$remote_id";
                # Extend the timeout for snapshots (default is one
                # minute, snapshots get 15 minutes (mainly due to ARIN)).
                push(@pending_requests, [$snapshot_url, $remote_id_key, time(), {timeout => 900}]);
                $queued++;
                $id_to_rmd{$remote_id_key} = {
                    type  => 'prefetch',
                    value => $fqdn
                };
                $used_prefetch = 1;
                dprint("Submitted fetch for '$snapshot_url'");
                $snapshots_done = 0;
                $snapshot_count++;
            }
        }
        if (not $used_prefetch) {
            my $base_url = "$url_prefix/.well-known";
            my $index_url = "$base_url/erik/index/$fqdn";
            dprint("Submitting fetch for '$index_url'");
            $remote_id++;
            my $remote_id_key = "remote_id_$remote_id";
            push(@pending_requests, [$index_url, $remote_id_key, time()]);
            $queued++;
            $id_to_rmd{$remote_id_key} = {
                type  => 'fqdn',
                value => $fqdn
            };
            dprint("Submitted fetch for '$index_url'");
        }
        if (not -e "$dir/$fqdn") {
            mkdir "$dir/$fqdn"
                or die "Unable to make directory '$dir/$fqdn': $!";
        }
        my $time = time();
        my $res = utime($time, $time, "$dir/$fqdn");
        if (not $res) {
            dprint("Unable to set modification time on ".
                   "cache directory for '$fqdn'");
        }
    }

    my ($res, $id);
    my $timer = IO::Async::Timer::Periodic->new(
        interval => 0.1,
        on_tick  => sub {
            if (@pending_requests) {
                my $qs = int(($snapshots_done ? $procs : $snapshot_procs) * $adaptive_mult);
                if ($qs < 1) {
                    $qs = 1;
                }
                my $push = $qs - ($sent - $received);
                dprint("Push count is '$push' ($received/$sent, $queued, $snapshot_count)");
                while (($push-- > 0) and @pending_requests) {
                    my $next_url = $pending_requests[0]->[0];
                    if ($snapshots_done or ($next_url =~ /\/snapshot\//)) {
                        my $pr_data = shift @pending_requests;
                        my ($url, $remote_id_key, $queued, $args) = @{$pr_data};
                        my $all_data = "";
                        my $sent_time = time();
                        $http->do_request(
                            uri         => URI->new($url),
                            on_header   => sub {
                                my ($headers) = @_;
                                my $resp = $headers;
                                my $all_length = $resp->headers()->header('Content-Length');
                                my $received = 0;
                                my $last_int_pct = 0;
                                dprint("Received headers for '$url' (size is '$all_length')");
                                return sub { my ($data) = @_;
                                            if ($data) {
                                                my $ld = length($data);
                                                $received += $ld;
                                                my $pct = sprintf('%.2f', (($received / $all_length) * 100));
                                                if (int($pct) > $last_int_pct) {
                                                    $last_int_pct = int($pct);
                                                    dprint("Received data for '$url' ($pct%)"); 
                                                }
                                                $all_data .= $data;
                                            } else {
                                                dprint("Received complete response for '$url'");
                                                if ($url =~ /\/snapshot\//) {
                                                    $snapshot_count--;
                                                    if ($snapshot_count == 0) {
                                                        $snapshots_done = 1;
                                                    }
                                                }
                                                $resp->content($all_data);
                                                push @remote_responses, [$resp, $remote_id_key];
                                            } };
                            },
                            on_error => sub {
                                my ($failure) = @_;
                                my $error = time();
                                my $sent_to_error = sprintf("%.2f", $error - $sent_time);
                                my $queued_to_error = sprintf("%.2f", $error - $queued);
                                dprint("HTTP error: '$url', '$failure', '$sent_to_error', '$queued_to_error'");

                                my $resp = HTTP::Response->new();
                                $resp->code(504);
                                $resp->content($failure);
                                my $req = HTTP::Request->new();
                                $req->uri($url);
                                $resp->request($req);
                                push @remote_responses, [$resp, $remote_id_key];
                                if ($url =~ /\/snapshot\//) {
                                    $snapshot_count--;
                                    if ($snapshot_count == 0) {
                                        $snapshots_done = 1;
                                    }
                                }
                                if ($adaptive_procs) {
                                    dprint("Halving queue size ($adaptive_mult)");
                                    $adaptive_mult *= 0.5;
                                }
                            },
                            %{$args || {}},
                        );
                        $sent++;
                        dprint("Actually submitted request for $url");
                    } else {
                        dprint("Not submitting pending requests (waiting for snapshot completion)");
                        last;
                    }
                }
            }
            my $ts = POSIX::strftime('%F %T', gmtime(time()));
            dprint("Running periodic timer loop ($ts): processed $received/$sent (queued $queued)");
            while ((@remote_responses and ($res, $id) = @{shift @remote_responses})
                    or (@local_responses and ($res, $id) = @{shift @local_responses})) {
                if ($id =~ /^remote_/) {
                    $received++;
                }
                my $rmd = delete $id_to_rmd{$id};
                my $index_url = $res->request()->uri();
                my ($type, $value) = @{$rmd}{qw(type value)};
                if ($type eq 'prefetch') {
                    my $fqdn = $value;
                    if (not $res->is_success()) {
                        dprint("Unable to fetch snapshot/TTQ for '$fqdn': ".Dumper($res));
                        print STDERR "Unable to fetch snapshot/TTQ for '$fqdn': ".$res->status_line()."\n";
                        print STDERR "Falling back to non-snapshot synchronisation for '$fqdn'\n";
                    } else {
                        $fqdn_to_ler{$fqdn} = 1;
                        my %hash_to_path;
                        eval {
                            my $ft = File::Temp->new();
                            my $fn = $ft->filename();
                            write_file($fn, $res->content());
                            $ft->flush();
                            my $res = rename($fn, "$fn.gz");
                            if (not $res) {
                                die "Unable to move file";
                            }
                            my $z = IO::Uncompress::Gunzip->new("$fn.gz");
                            if (not $z) {
                                die "$GunzipError";
                            }
                            for (;;) {
                                my $buffer;
                                my $n = asn_read($z, $buffer);
                                if (not $n) {
                                    last;
                                }
                                my $wrote = 0;
                                my $cms = APNIC::RPKI::CMS->new();
                                eval { $cms->decode($buffer) };
                                if (not $@) {
                                    my $type = eval { $cms->type(); };
                                    $type ||= '';
                                    if ($type eq 'mft') {
                                        my $mft =
                                            APNIC::RPKI::Manifest->new();
                                        $mft->decode($cms->payload()->{'content'}->{'encapContentInfo'}->{'eContent'});
                                        my ($mft_path) =
                                            ($cms->payload()->{'content'}->{'certificates'}->[0]
                                            =~ /.*rsync:\/\/(.*?mft)/);
                                        my ($pdir) = ($mft_path =~ /(.*)\//);
                                        mkpath("$out_dir/$pdir");
                                        write_file("$out_dir/$mft_path", $buffer);
                                        dprint("Wrote object directly ($out_dir/$mft_path)");
                                        $wrote = 1;
                                        $ler_file_count++;
                                        $ler_file_reliance++;
                                        for my $file (@{$mft->files()}) {
                                            my ($filename, $hash) =
                                                @{$file}{qw(filename hash)};
                                            my $final_path = "$out_dir/$pdir/$filename";

                                            my $raw_hash = pack('H*', $hash);
                                            my $path_segment =
                                                encode_base64url($raw_hash);
                                            if (-e "$ler/$path_segment") {
                                                dprint("Object written to local relay already");
                                                my $ress = rename("$ler/$path_segment",
                                                                  $final_path);
                                                if (not $ress) {
                                                    die "Unable to move file";
                                                }
                                                $ler_file_reliance++;
                                            } else {
                                                $hash_to_path{$hash} = $final_path;
                                                dprint("Adding manifest file to lookup: $hash -> $final_path");
                                            }
                                        }
                                    }
                                }
                                if (not $wrote) {
                                    my $digest = Digest::SHA->new(256);
                                    $digest->add($buffer);
                                    my $digest_data = $digest->clone()->digest();
                                    my $hexdigest = lc $digest->clone()->hexdigest();
                                    if (my $path = delete $hash_to_path{$hexdigest}) {
                                        dprint("Found object path in lookup, writing directly ($path)");
                                        write_file($path, $buffer);
                                        $ler_file_count++;
                                        $ler_file_reliance++;
                                    } else {
                                        my $path_segment = encode_base64url($digest_data);
                                        write_file("$ler/$path_segment", $buffer);
                                        dprint("Wrote object to local relay ($path_segment) ($hexdigest)");
                                        $ler_file_count++;
                                    }
                                }
                            }
                        };
                        if (my $error = $@) {
                            warn "Unable to process snapshot/TTQ for '$fqdn': $error";
                            warn "Falling back to standard synchronisation for '$fqdn'";
                        }
                    }
                    if (($index_url =~ /\/snapshot\//)
                            and $snapshots_only) {
                        dprint("Skipping tree synchronisation after loading snapshot");
                    } else {
                        dprint("Generating partition data for '$fqdn' for synchronising, after prefetch");
                        my $cache_dir = $dir;
                        my $httpd_dir = tempdir();
                        my $updater =
                            APNIC::RPKI::Erik::Updater->new(
                                $cache_dir, $httpd_dir
                            );
                        my ($fpmf, undef) = $updater->synchronise($fqdn);
                        $fqdn_to_pt_to_mft_to_file{$fqdn} = $fpmf;
                        dprint("Generated partition data for '$fqdn' for synchronising, after prefetch");

                        my $base_url = "$url_prefix/.well-known";
                        my $index_url = "$base_url/erik/index/$fqdn";
                        dprint("Submitting fetch for '$index_url'");
                        $remote_id++;
                        my $remote_id_key = "remote_id_$remote_id";
                        push(@pending_requests, [$index_url, $remote_id_key, time()]);
                        $queued++;
                        $id_to_rmd{$remote_id_key} = {
                            type  => 'fqdn',
                            value => $fqdn
                        };
                        dprint("Submitted fetch for '$index_url'");
                    }
                } elsif ($type eq 'fqdn') {
                    my $fqdn = $value;
                    my $pt_to_mft_to_file = $fqdn_to_pt_to_mft_to_file{$fqdn};
                    if (not $res->is_success()) {
                        dprint("Unable to fetch index for '$fqdn': ".Dumper($res));
                        print STDERR "Unable to fetch index for '$fqdn': ".$res->status_line()."\n";
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
                                if ($gc) {
                                    for my $mft (keys %{$pt_to_mft_to_file->{$pt}}) {
                                        for my $file (@{$pt_to_mft_to_file->{$pt}->{$mft}}) {
                                            $relevant_files{$file} = 1;
                                        }
                                        my $mft_file = $mft;
                                        $mft_file =~ s/rsync:..//;
                                        $relevant_files{$mft_file} = 1;
                                    }
                                }
                            } else {
                                dprint("Processing partition '$hash' with size '$size'");
                                my $partition_url =
                                    hash_to_url($url_prefix, $hash);
                                dprint("Submitting fetch for partition '$partition_url'");
                                $remote_id++;
                                my $remote_id_key = "remote_id_$remote_id";
                                push(@pending_requests, [$partition_url, $remote_id_key, time()]);
                                $queued++;
                                $id_to_rmd{$remote_id_key} = {
                                    type  => 'partition',
                                    value => [$fqdn, $hash, $size]
                                };
                                dprint("Submitted fetch for partition '$partition_url'");
                            }
                        }
                    }
                } elsif ($type eq 'partition') {
                    my ($fqdn, $hash, $size) = @{$value};
                    my $partition_url = $res->request()->uri();
                    if (not $res->is_success()) {
                        dprint("Unable to fetch partition for '$fqdn' ('$hash'): ".Dumper($res));
                        print STDERR "Unable to fetch partition for '$fqdn' ('$hash'): ".$res->status_line()."\n";
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
                            dprint("Processing manifest '$location' (number ".
                                "'$mftnum', size '$size')");
                            my $uri = URI->new($location);
                            my $path = $uri->path();
                            $path =~ s/^\///;
                            $path = $uri->host()."/$path";
                            if ($gc) {
                                $relevant_files{$path} = 1;
                            }
                            my ($pdir) = ($path =~ /^(.*)\//);
                            my ($file) = ($path =~ /^.*\/(.*)$/);
                            mkpath("$out_dir/$pdir");
                            my $get = 0;
                            my $read_path;
                            if (-e "$out_dir/$path") {
                                # Written by prefetch already, so no
                                # need to fetch.
                                $read_path = "$out_dir/$path";
                            } elsif (-e "$dir/$path") {
                                my $digest = Digest::SHA->new(256);
                                $digest->addfile("$dir/$path");
                                my $content = lc $digest->hexdigest();
                                if ($content ne $hash) {
                                    $get = 1;
                                } else {
                                    $read_path = "$dir/$path";
                                }
                            } else {
                                $get = 1;
                            }
                            if ($get) {
                                my $handled = 0;
                                dprint("Need to fetch manifest '$location' ($dir/$path)");
                                my $o_path = hash_to_local_path($ler, $hash);
                                if (-e $o_path) {
                                    $ler_file_reliance++;
                                    dprint("Found '$location' locally");
                                    my $req = HTTP::Request->new();
                                    $req->uri(URI->new("file://$o_path"));
                                    my $res = HTTP::Response->new();
                                    $res->request($req);
                                    $res->code(204);
                                    $local_id++;
                                    my $local_id_key = "local_id_$local_id";
                                    $id_to_rmd{$local_id_key} = {
                                        type  => 'manifest',
                                        value => [$fqdn, $entry, $path, $pdir]
                                    };
                                    push @local_responses, [$res, $local_id_key];
                                    $handled = 1;
                                }
                                if (not $handled and $fqdn_to_ler{$fqdn}) {
                                    dprint("Did not find '$location' locally");
                                }
                                if (not $handled) {
                                    my $manifest_url =
                                        hash_to_url($url_prefix, $hash);
                                    dprint("Submitting fetch for manifest '$manifest_url'");

                                    $remote_id++;
                                    my $remote_id_key = "remote_id_$remote_id";
                                    push(@pending_requests, [$manifest_url, $remote_id_key, time()]);
                                    $queued++;
                                    $id_to_rmd{$remote_id_key} = {
                                        type  => 'manifest',
                                        value => [$fqdn, $entry, $path, $pdir]
                                    };

                                    dprint("Submitted fetch for manifest '$manifest_url'");
                                }
                            } else {
                                dprint("Do not need to fetch manifest '$location'");

                                if ($gc) {
                                    my $mdata = $openssl->verify_cms($read_path);
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
                    }
                } elsif ($type eq 'manifest') {
                    my ($fqdn, $entry, $path, $pdir) = @{$value};
                    my $manifest_url = $res->request()->uri();
                    if (not $res->is_success()) {
                        dprint("Unable to fetch manifest for '$path': ".Dumper($res));
                        print STDERR "Unable to fetch manifest for '$path': ".$res->status_line()."\n";
                        $ok = 0;
                    } else {
                        chdir $dir or die $!;
                        my $manifest;
                        if (-e $path) {
                            my $cmft = APNIC::RPKI::Manifest->new();
                            my $cmft_data = $openssl->verify_cms($path);
                            $cmft->decode($cmft_data);
                            $manifest = APNIC::RPKI::Manifest->new();
                            if ($res->code() == 204) {
                                my $rpath = $res->request()->uri()->as_string();
                                $rpath =~ s/^file:\/\///;
                                my $nmft_data = $openssl->verify_cms($rpath);
                                $manifest->decode($nmft_data);
                            } else {
                                my $ft = File::Temp->new();
                                my $fn = $ft->filename();
                                write_file($fn, $res->decoded_content());
                                my $nmft_data = $openssl->verify_cms($fn);
                                $manifest->decode($nmft_data);
                            }
                            if ($manifest->manifest_number() < $cmft->manifest_number()) {
                                dprint("Remote manifest is different, ".
                                       "but has smaller manifest ".
                                       "number, skipping");
                                next;
                            } elsif ($manifest->this_update() < $cmft->this_update()) {
                                dprint("Remote manifest is different, ".
                                       "but has older thisUpdate, ".
                                       "skipping");
                                next;
                            }
                        }
                        chdir $out_dir or die $!;
                        if ($res->code() == 204) {
                            my $rpath = $res->request()->uri()->as_string();
                            $rpath =~ s/^file:\/\///;
                            my $ress = rename($rpath, $path);
                            if (not $ress) {
                                die "Unable to move file: $!";
                            }
                        } else {
                            write_file($path, $res->decoded_content());
                        }
                        dprint("Fetched manifest '$manifest_url'");
                        dprint("Wrote manifest to path '$path'");

                        if (not $manifest) {
                            my $mdata = $openssl->verify_cms($path);
                            $manifest = APNIC::RPKI::Manifest->new();
                            $manifest->decode($mdata);
                        }
                        my @files = @{$manifest->files() || []};
                        my $file_count = scalar @files;
                        dprint("Manifest file count: '$file_count'");
                        chdir $dir or die $!;
                        for my $file (@files) {
                            my $filename = $file->{'filename'};
                            dprint("Processing file '$filename'");
                            my $hash = $file->{'hash'};
                            my $fpath = "$pdir/$filename";
                            my $get = 0;
                            if (-e "$out_dir/$fpath") {
                                # Written by prefetch already, so no
                                # need to fetch.
                            } elsif (-e "$dir/$fpath") {
                                my $digest = Digest::SHA->new(256);
                                $digest->addfile("$dir/$fpath");
                                my $content = lc $digest->hexdigest();
                                if ($content ne $hash) {
                                    $get = 1;
                                }
                            } else {
                                $get = 1;
                            }
                            if ($gc) {
                                $relevant_files{$fpath} = 1;
                            }
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
                                    $res->code(204);
                                    $local_id++;
                                    my $local_id_key = "local_id_$local_id";
                                    $id_to_rmd{$local_id_key} = {
                                        type  => 'object',
                                        value => [$fqdn, $fpath]
                                    };
                                    push @local_responses, [$res, $local_id_key];
                                    $handled = 1;
                                }
                                if (not $handled and $fqdn_to_ler{$fqdn}) {
                                    dprint("Did not find '$filename' locally");
                                }
                                if (not $handled) {
                                    my $o_url =
                                        hash_to_url($url_prefix, $hash);
                                    dprint("Submitting fetch for file '$o_url'");

                                    $remote_id++;
                                    my $remote_id_key = "remote_id_$remote_id";
                                    push(@pending_requests, [$o_url, $remote_id_key, time()]);
                                    $queued++;
                                    $id_to_rmd{$remote_id_key} = {
                                        type  => 'object',
                                        value => [$fqdn, $fpath]
                                    };

                                    dprint("Submitted fetch for file '$o_url'");
                                }
                            } else {
                                dprint("Do not need to fetch file '$fpath'");
                            }
                        }
                    }
                } elsif ($type eq 'object') {
                    my ($fqdn, $fpath) = @{$value};
                    my $object_url = $res->request()->uri();
                    if (not $res->is_success()) {
                        dprint("Unable to fetch object for '$fpath': ".Dumper($res));
                        print STDERR "Unable to fetch object for '$fpath': ".$res->status_line()."\n";
                        $ok = 0;
                    } else {
                        chdir $out_dir or die $!;
                        if ($res->code() == 204) {
                            my $rpath = $res->request()->uri()->as_string();
                            $rpath =~ s/^file:\/\///;
                            my $ress = rename($rpath, $fpath);
                            if (not $ress) {
                                die "Unable to move file: $!";
                            }
                        } else {
                            write_file($fpath, $res->decoded_content());
                        }
                        dprint("Fetched file '$object_url'");
                        dprint("Wrote file to path '$fpath'");
                    }
                }
            }
            if (($sent == $received) and ($queued == $received)) {
                dprint("Finished processing all requests ($received/$sent/$queued)");
                $loop->stop();
            }
        }
    );
    $loop->add($timer);
    $timer->start();
    dprint("Started running loop");
    $loop->run();
    dprint("Stopped running loop");
    $loop->remove($timer);
    dprint("Removed timer notifier");
    $loop->remove($http);
    dprint("Removed HTTP notifier");
    $http  = undef;
    dprint("Undefined HTTP notifier");
    $timer = undef;
    dprint("Undefined timer notifier");
    $loop  = undef;
    dprint("Undefined loop");

    if (not $ok) {
        return;
    }

    if ($gc and $ok) {
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
        }
    }

    chdir $cwd;

    dprint("Completed synchronisation");

    return { success             => $ok,
             local_file_count    => $ler_file_count,
             local_file_reliance => $ler_file_reliance };
}

1;
