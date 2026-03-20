package APNIC::RPKI::Erik::Updater;

use warnings;
use strict;

use APNIC::RPKI::Manifest;
use APNIC::RPKI::Erik::Index;
use APNIC::RPKI::Erik::Partition;
use APNIC::RPKI::Utils qw(dprint);
use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::X509;
use APNIC::RPKI::CMS;

use Cwd qw(cwd);
use Digest::SHA;
use File::Find;
use File::Path qw(mkpath);
use File::Slurp qw(read_file write_file);
use IO::Compress::Gzip;
use JSON::XS qw(encode_json);
use List::Util qw(first);
use MIME::Base64 qw(encode_base64url);

sub new
{
    my ($class, $cache_dir, $httpd_dir, %args) = @_;

    my $self = {
        cache_dir => $cache_dir,
        httpd_dir => $httpd_dir,
        openssl   => APNIC::RPKI::OpenSSL->new(),
        %args
    };
    bless $self, $class;
    return $self;
}

sub write_rpki_file
{
    my ($self, $source_path, $filename, $content) = @_;

    dprint("Writing RPKI file ($filename)");

    my $dir = cwd();
    my $dir_count = $self->{'dir_count'} || 0;
    my $cc = $self->{'char_count'} || 0;
    my $httpd_dir = $self->{'httpd_dir'};
    my $ni_path = ".well-known/ni/sha-256";
    my $current_dir = "$httpd_dir/$ni_path";

    my $remaining_fn = $filename;
    if ($dir_count and not $cc) {
        die "If dir_count is set, char_count must also be set";
    }
    while ($dir_count--) {
        my ($next_chars) = ($remaining_fn =~ /^(.{$cc})/);
        $remaining_fn =~ s/^.{$cc}//;
        if (not $remaining_fn) {
            die "Too many characters taken from filename";
        }
        eval { mkpath("$current_dir/$next_chars") };
        if (my $error = $@) {
            die "Unable to make NI directory: $error";
        }
        $current_dir = "$current_dir/$next_chars";
    }

    chdir $current_dir;
    # todo: these two operations should happen atomically.
    unlink $remaining_fn;
    my $new_path = "$current_dir/$remaining_fn";
    if ($source_path) {
        my $res = symlink($source_path, $new_path);
        if (not $res) {
            die "Unable to link $source_path into httpd directory: $!";
        }
    } else {
        write_file($new_path, $content);
    }
    dprint("Linked file to '$new_path'");

    if ($source_path) {
        my @stat = stat($source_path);
        my $atime = $stat[8];
        my $mtime = $stat[9];
        utime($atime, $mtime, $new_path);
    }

    chdir $dir;

    return $new_path;
}

sub synchronise
{
    my ($self, $fqdn_to_sync) = @_;

    my $dir = cwd();

    my $cache_dir = $self->{'cache_dir'};
    my $httpd_dir = $self->{'httpd_dir'};
    my $openssl   = $self->{'openssl'};

    my $ni_path = ".well-known/ni/sha-256";
    my $index_path = ".well-known/erik/index";
    if (not $fqdn_to_sync) {
        eval { mkpath("$httpd_dir/$ni_path") };
        if (my $error = $@) {
            die "Unable to make NI directory: $error";
        }
        eval { mkpath("$httpd_dir/$index_path") };
        if (my $error = $@) {
            die "Unable to make Erik index directory: $error";
        }
    }

    if ($cache_dir !~ /^\//) {
        $cache_dir = "$dir/$cache_dir";
    }
    dprint("Cache directory is '$cache_dir'");
    chdir $cache_dir or die $!;
    my $find_dir = $fqdn_to_sync || "";
    my %fqdn_to_pt_to_mft_to_file;
    my %fqdn_to_manifests;
    my %fqdn_to_path;
    my %written_files;

    my @fqdn_to_manifests;

    find(sub {
        my $path = $File::Find::name;
        if (-d $path) {
            return;
        }
        my $relpath = $path;
        dprint("Path is '$path'");
        $relpath =~ s/^$cache_dir\///;
        dprint("Relative path is '$relpath'");
        my ($fqdn) = ($relpath =~ /^(.*?)\//);
        dprint("FQDN is '$fqdn'");
        my $file = $relpath;

        dprint("Processing file '$file' in updater");
        $fqdn_to_manifests{$fqdn} ||= [];
        my ($ext) = ($file =~ /.*\.(.*?)$/);

        my $digest = Digest::SHA->new(256);
        $digest->addfile($path);
        my $digest_data = $digest->clone()->digest();
        my $digest_hexdata = $digest->clone()->hexdigest();
        my $path_segment = encode_base64url($digest_data);

        if ($ext eq "mft") {
            dprint("File is a manifest");
            push @{$fqdn_to_manifests{$fqdn}},
                 [$file, $digest_hexdata];
        }

        if (not $fqdn_to_sync) {
            my $new_path =
                $self->write_rpki_file("$cache_dir/$file",
                                    $path_segment);
            push @{$fqdn_to_path{$fqdn}}, $new_path;
            $written_files{$new_path} = 1;
        }

    }, "$cache_dir/$find_dir");

    my @partition_ret_data;
    for my $fqdn (keys %fqdn_to_manifests) {
        my @manifest_details = @{$fqdn_to_manifests{$fqdn}};
        my $mc = scalar @manifest_details;

        my %partitions;
        my %mft_to_files;

        for my $manifest_detail (sort { $a->[1] cmp $b->[1] } @manifest_details) {
            my ($file, $hash) = @{$manifest_detail};
            dprint("Processing manifest '$file' for partitioning");

            my $cms = APNIC::RPKI::CMS->new();
            my $mft_data = read_file($file);
            $cms->decode($mft_data);
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

            my $tu = $manifest->this_update();
            my %mldet = (
                hash            => $hash,
                size            => ((stat($file))[7]),
                aki             => $aki,
                manifest_number => $manifest->manifest_number(),
                this_update     => $tu,
                locations       => [ "rsync://$file" ]
            );
            my ($dir) = ($file =~ /^(.*)\/.*/);
            $mft_to_files{"rsync://$file"} =
                [ map { $dir."/".$_->{'filename'} } @{$manifest->files()} ];

            my @aki_chars = split //, $aki;
            my $first_byte = $aki_chars[0].$aki_chars[1];
            my $partition = $partitions{$first_byte};
            if (not $partition) {
                my $partition = APNIC::RPKI::Erik::Partition->new();
                $partition->partition_time($tu);
                $partition->manifest_list([ \%mldet ]);
                $partitions{$first_byte} = $partition;
            } else {
                my $current_tu = $partition->partition_time();
                if ($tu > $current_tu) {
                    $partition->partition_time($tu);
                }
                push @{$partition->manifest_list()}, \%mldet;
            }
        }

        my @pds;
        my %pt_to_mft_to_file;
        my $i = 1;
        my $len = scalar(values %partitions);
        for my $partition (values %partitions) {
            dprint("Processing partition $i/$len");
            $i++;
            my $pcontent = $partition->encode();

            my $pdigest = Digest::SHA->new(256);
            $pdigest->add($pcontent);
            my $pdigest_data = $pdigest->clone()->digest();
            my $pdigest_hexdata = $pdigest->clone()->hexdigest();
            my $ppath_segment = encode_base64url($pdigest_data);

            if (not $fqdn_to_sync) {
                my $new_path = $self->write_rpki_file(
                    undef, $ppath_segment, $pcontent
                );
                $written_files{$new_path} = 1;
                dprint("Wrote new partition for manifest to '$new_path'");
            }

            my $index_partition_hash = $pdigest_hexdata;
            dprint("Index partition hash is '$index_partition_hash'");
            my $tu = $partition->partition_time();
            my $size = length($pcontent);
            push @pds, {
                hash        => $index_partition_hash,
                size        => $size,
                this_update => $partition->partition_time()
            };

            push @partition_ret_data,
                 [ $partition, $index_partition_hash, $size ];

            my $pt = "$index_partition_hash-$size";
            my @manifests = @{$partition->manifest_list()};
            my @mft_filenames =
                map { $_->{'locations'}->[0] }
                    @manifests;
            $pt_to_mft_to_file{$pt} =
                +{ map { $_ => $mft_to_files{$_} }
                    @mft_filenames };
        }

        my @tus = sort map { $_->{'this_update'} } @pds;
        my $latest_tu = $tus[$#tus];
        for my $pd (@pds) {
            delete $pd->{'this_update'};
        }
        my $index = APNIC::RPKI::Erik::Index->new();
        $index->index_scope($fqdn);
        $index->index_time($latest_tu);
        $index->partition_list(\@pds);
        my $icontent = $index->encode();

        if (not $fqdn_to_sync) {
            my $new_path = "$httpd_dir/$index_path/$fqdn";
            $written_files{$new_path} = 1;
            write_file($new_path, $icontent);
        }

        $fqdn_to_pt_to_mft_to_file{$fqdn} = \%pt_to_mft_to_file;
    }

    if ($fqdn_to_sync) {
        return ($fqdn_to_pt_to_mft_to_file{$fqdn_to_sync},
                \@partition_ret_data);
    }

    my $dir_count = $self->{'dir_count'} || 0;
    my $cc = $self->{'char_count'} || 0;

    my $md_path = "$httpd_dir/.well-known/erik/metadata";
    write_file($md_path,
               encode_json({ dir_count  => $dir_count,
                             char_count => $cc }));
    $written_files{$md_path} = 1;

    if ($self->{'write_snapshots'}) {
        for my $fqdn (keys %fqdn_to_path) {
            mkpath("$httpd_dir/.well-known/erik/snapshot");
            my $new_output_path =
                "$httpd_dir/.well-known/erik/snapshot/$fqdn";
            my $z = IO::Compress::Gzip->new(
                $new_output_path
            ) or die $!;
            for my $path (@{$fqdn_to_path{$fqdn}}) {
                open my $fh, "<", $path or die $!;
                binmode($fh);
                my $buffer;
                my $bytes;
                while ($bytes = read($fh, $buffer, 1024)) {
                    $z->syswrite($buffer) or die $!;
                }
            }
            $z->flush() or die $!;
            $written_files{$new_output_path} = 1;
            dprint("Wrote snapshot ($new_output_path)");
        }
    }

    if ($self->{'write_ttqs'}) {
        for my $fqdn (keys %fqdn_to_path) {
            mkpath("$httpd_dir/.well-known/erik/tail");
            for my $det ([300, "5min"],
                         [600, "10min"]) {
                my ($s, $file) = @{$det};
                mkpath("$httpd_dir/.well-known/erik/tail/$fqdn");
                my $new_output_path =
                    "$httpd_dir/.well-known/erik/tail/$fqdn/$file";
                my $z = IO::Compress::Gzip->new(
                    $new_output_path
                ) or die $!;
                my $now = time();
                my $threshold = $now - $s;
                for my $path (@{$fqdn_to_path{$fqdn}}) {
                    my $mtime = (stat($path))[9];
                    if ($mtime > $threshold) {
                        open my $fh, "<", $path or die $!;
                        binmode($fh);
                        my $buffer;
                        my $bytes;
                        while ($bytes = read($fh, $buffer, 1024)) {
                            $z->syswrite($buffer) or die $!;
                        }
                    }
                }
                $z->flush() or die $!;
                $written_files{$new_output_path} = 1;
                dprint("Wrote TTQ ($new_output_path)");
            }
        }
    }

    chdir "/" or die $!;
    find(sub {
        my $path = $File::Find::name;
        if ((-f $path) and (not $written_files{$path})) {
            dprint("Removing '$path' (deleted)");
            unlink $path or die $!;
        }
    }, $httpd_dir);

    chdir $dir;

    return 1;
}

1;
