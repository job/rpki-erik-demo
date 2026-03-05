package APNIC::RPKI::Erik::Updater;

use warnings;
use strict;

use APNIC::RPKI::Manifest;
use APNIC::RPKI::Erik::Index;
use APNIC::RPKI::Erik::Partition;
use APNIC::RPKI::Utils qw(dprint);
use APNIC::RPKI::OpenSSL;

use Cwd qw(cwd);
use Digest::SHA;
use File::Path qw(mkpath);
use File::Slurp qw(read_file write_file);
use IO::Compress::Gzip;
use JSON::XS qw(encode_json);
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
    chdir $dir;

    return $new_path;
}

sub synchronise
{
    my ($self) = @_;

    my $dir = cwd();

    my $cache_dir = $self->{'cache_dir'};
    my $httpd_dir = $self->{'httpd_dir'};
    my $openssl   = $self->{'openssl'};

    my $ni_path = ".well-known/ni/sha-256";
    eval { mkpath("$httpd_dir/$ni_path") };
    if (my $error = $@) {
        die "Unable to make NI directory: $error";
    }
    my $index_path = ".well-known/erik/index";
    eval { mkpath("$httpd_dir/$index_path") };
    if (my $error = $@) {
        die "Unable to make Erik index directory: $error";
    }

    chdir $cache_dir or die $!;
    my @files = `find . -type f`;
    for (@files) {
        chomp;
        s/^\.\///;
    }
    my %fqdn_to_pd;
    my %fqdn_to_manifests;
    my %fqdn_to_path;
    my %written_files;
    my $file_count = scalar(@files);
    dprint("Updater file count: '$file_count'");

    my @fqdn_to_manifests;

    for my $file (@files) {
        dprint("Processing file '$file'");
        my ($fqdn) = ($file =~ /^(.*?)\//);
        $fqdn_to_pd{$fqdn} ||= [];
        $fqdn_to_manifests{$fqdn} ||= [];
        my ($ext) = ($file =~ /\.([a-z]*)$/);

        my $digest = Digest::SHA->new(256);
        $digest->addfile($file);
        my $digest_data = $digest->clone()->digest();
        my $digest_hexdata = $digest->clone()->hexdigest();
        my $path_segment = encode_base64url($digest_data);

        if ($ext eq "mft") {
            dprint("File is a manifest");
            push @{$fqdn_to_manifests{$fqdn}},
                 [$file, $digest_hexdata];
        }

        my $new_path =
            $self->write_rpki_file("$cache_dir/$file",
                                   $path_segment);
        push @{$fqdn_to_path{$fqdn}}, $new_path;
        $written_files{$new_path} = 1;
    }

    my $mpp = $self->{'mft_per_partition'} || 1;
    my $tp = $self->{'total_partitions'};

    for my $fqdn (keys %fqdn_to_pd) {
        my @manifest_details = @{$fqdn_to_manifests{$fqdn}};
        my $mc = scalar @manifest_details;
        if (defined $tp) {
            $mpp = int(($mc / $tp) + 1);
            dprint("Total partition count defined ($tp): ".
                   "there are $mc manifests, so will use $mpp ".
                   "manifests per partition");
        }
        my @partitions = @{$fqdn_to_pd{$fqdn}};
        for my $manifest_detail (@manifest_details) {
            my ($file, $hash) = @{$manifest_detail};

	    my $mdata = $openssl->verify_cms($file);
	    my $manifest = APNIC::RPKI::Manifest->new();
	    $manifest->decode($mdata);
            push @{$manifest_detail}, $manifest;
        }
        # Sort manifest details, so that older (stabler) manifests are
        # bundled together.
        @manifest_details =
            sort { $a->[2]->this_update() <=> $b->[2]->this_update() }
                @manifest_details;
        for my $manifest_detail (@manifest_details) {
            my ($file, $hash, $manifest) = @{$manifest_detail};
            my $tu = $manifest->this_update();
            my %mldet = (
                hash            => $hash,
                size            => ((stat($file))[7]),
                aki             => "aki",
                manifest_number => $manifest->manifest_number(),
                this_update     => $tu,
                locations       => [ "rsync://$file" ]
            );

            if (@partitions) {
                my $partition = $partitions[$#partitions];
                if (@{$partition->manifest_list()} >= $mpp) {
                    my $partition = APNIC::RPKI::Erik::Partition->new();
                    $partition->partition_time($tu);
                    $partition->manifest_list([ \%mldet ]);
                    push @partitions, $partition;
                } else {
                    my $current_tu = $partition->partition_time();
                    if ($tu > $current_tu) {
                        $partition->partition_time($tu);
                    }
                    push @{$partition->manifest_list()}, \%mldet;
                }
            } else {
                my $partition = APNIC::RPKI::Erik::Partition->new();
                $partition->partition_time($tu);
                $partition->manifest_list([ \%mldet ]);
                push @partitions, $partition;
            }
        }

        my @pds;
        for my $partition (@partitions) {
            my $pcontent = $partition->encode();

            my $pdigest = Digest::SHA->new(256);
            $pdigest->add($pcontent);
            my $pdigest_data = $pdigest->clone()->digest();
            my $pdigest_hexdata = $pdigest->clone()->hexdigest();
            my $ppath_segment = encode_base64url($pdigest_data);

            my $new_path = $self->write_rpki_file(
                undef, $ppath_segment, $pcontent
            );
            $written_files{$new_path} = 1;
            dprint("Wrote new partition for manifest to '$new_path'");

            my $index_partition_hash = $pdigest_hexdata;
            dprint("Index partition hash is '$index_partition_hash'");
            my $tu = $partition->partition_time();
            push @pds, {
                hash        => $index_partition_hash,
                size        => length($pcontent),
                this_update => $partition->partition_time()
            };
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

        my $new_path = "$httpd_dir/$index_path/$fqdn";
        $written_files{$new_path} = 1;
        write_file($new_path, $icontent);
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

    chdir "/" or die $!;
    @files = `find $httpd_dir -type f`;
    for my $file (@files) {
        chomp $file;
        $file =~ s/^\.\///;
        if (not $written_files{$file}) {
            dprint("Removing '$file' (deleted)");
            unlink $file or die $!;
        }
    }

    chdir $dir;

    return 1;
}

1;
