package APNIC::RPKI::Erik::Updater;

use warnings;
use strict;

use APNIC::RPKI::Manifest;
use APNIC::RPKI::Erik::Index;
use APNIC::RPKI::Erik::Partition;
use APNIC::RPKI::Utils qw(dprint);

use Cwd qw(cwd);
use Digest::SHA;
use File::Slurp qw(read_file write_file);
use MIME::Base64 qw(encode_base64url);

sub new
{
    my ($class, $cache_dir, $httpd_dir) = @_;

    my $self = {
        cache_dir => $cache_dir,
        httpd_dir => $httpd_dir,
        openssl   => APNIC::RPKI::OpenSSL->new(),
    };
    bless $self, $class;
    return $self;
}

sub synchronise
{
    my ($self) = @_;

    my $dir = cwd();

    my $cache_dir = $self->{'cache_dir'};
    my $httpd_dir = $self->{'httpd_dir'};
    my $openssl   = $self->{'openssl'};

    my $ni_path = ".well-known/ni/sha-256";
    my $res = system("mkdir -p $httpd_dir/$ni_path");
    if ($res != 0) {
        die "Unable to make NI directory";
    }
    my $index_path = ".well-known/erik/index";
    $res = system("mkdir -p $httpd_dir/$index_path");
    if ($res != 0) {
        die "Unable to make Erik index directory";
    }

    chdir $cache_dir or die $!;
    my @files = `find . -type f`;
    for (@files) {
        chomp;
        s/^\.\///;
    }
    my %fqdn_to_pd;
    my %written_files;
    my $file_count = scalar(@files);
    dprint("Updater file count: '$file_count'");
    for my $file (@files) {
        dprint("Processing file '$file'");
        my ($fqdn) = ($file =~ /^(.*?)\//);
        $fqdn_to_pd{$fqdn} ||= [];
        my ($ext) = ($file =~ /\.([a-z]*)$/);

        my $digest = Digest::SHA->new(256);
        $digest->addfile($file);
        my $digest_data = $digest->clone()->digest();
        my $digest_hexdata = $digest->clone()->hexdigest();
        my $path_segment = encode_base64url($digest_data);

        if ($ext eq "mft") {
            dprint("File is a manifest");
	    my $mdata = $openssl->verify_cms($file);
	    my $manifest = APNIC::RPKI::Manifest->new();
	    $manifest->decode($mdata);
            
            my $partition = APNIC::RPKI::Erik::Partition->new();
            my $tu = $manifest->this_update();
            $partition->partition_time($tu);
            my $partition_hash = $digest_hexdata;
            dprint("Partition manifest list hash is '$partition_hash'");
            $partition->manifest_list([{
                hash            => $partition_hash,
                size            => ((stat($file))[7]),
                aki             => "aki",
                manifest_number => $manifest->manifest_number(),
                this_update     => $tu,
                locations       => [ "rsync://$file" ]
            }]);
            my $pcontent = $partition->encode();

            my $pdigest = Digest::SHA->new(256);
            $pdigest->add($pcontent);
            my $pdigest_data = $pdigest->clone()->digest();
            my $pdigest_hexdata = $pdigest->clone()->hexdigest();
            my $ppath_segment = encode_base64url($pdigest_data);

            my $new_path = "$httpd_dir/$ni_path/$ppath_segment";
            $written_files{$new_path} = 1;
            write_file($new_path, $pcontent);
            dprint("Wrote new partition for manifest to '$new_path'");

            write_file("/tmp/$ppath_segment", $pcontent);

            my $index_partition_hash = $pdigest_hexdata;
            dprint("Index partition hash is '$index_partition_hash'");
            push @{$fqdn_to_pd{$fqdn}}, {
                hash        => $index_partition_hash,
                size        => length($pcontent),
                this_update => $tu
            };
        }

        my $new_path = "$httpd_dir/$ni_path/$path_segment";
        $written_files{$new_path} = 1;
        my $res = system("cp $file $new_path");
        if ($res != 0) {
            die "Unable to copy $file into httpd directory";
        }
        dprint("Wrote file to '$new_path'");
    }

    for my $fqdn (keys %fqdn_to_pd) {
        my @pds = @{$fqdn_to_pd{$fqdn}};
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
