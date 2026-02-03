package APNIC::RPKI::OpenSSL;

use warnings;
use strict;

use File::Slurp qw(read_file);
use File::Temp;
use List::Util qw(first);
use Net::CIDR::Set;
use Set::IntSpan;

use APNIC::RPKI::Utilities qw(system_ad);

our $VERSION = '0.1';

my @PATHS = qw(
    /usr/local/ssl/bin/openssl
    /usr/bin/openssl
);

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;

    if (not $self->{'path'}) {
        $self->{'path'} =
            ((first { -x $_ } @PATHS) || $PATHS[0]);
    }

    bless $self, $class;
    return $self;
}

sub get_openssl_path
{
    my ($self) = @_;

    return $self->{'path'};
}

sub to_pem
{
    my ($self, $input_path) = @_;

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->get_openssl_path();
    system_ad("$openssl x509 -inform DER ".
              "-in $input_path ".
              "-outform PEM ".
              "-out $fn_output",
              $self->{'debug'});

    return read_file($fn_output);
}

sub verify_cms
{
    my ($self, $input, $ca_cert) = @_;

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $extra =
        (not defined $ca_cert)
            ? "-noverify"
            : "-CAfile $ca_cert";

    my $openssl = $self->get_openssl_path();
    system_ad("$openssl cms -verify -inform DER ".
              "-in $input ".
              " $extra ".
              "-out $fn_output",
              $self->{'debug'});

    my $data = read_file($fn_output);
    return $data;
}

sub get_ee_cert
{
    my ($self, $input) = @_;

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->get_openssl_path();
    system_ad("$openssl cms -verify -noverify -inform DER ".
              "-in $input ".
              "-certsout $fn_output",
              $self->{'debug'});

    return read_file($fn_output);
}

sub get_repository_url
{
    my ($self, $cert) = @_;

    my $ft_cert;
    my $fn_cert;
    if (-e $cert) {
        $fn_cert = $cert;
    } else {
        my $ft_cert = File::Temp->new();
        print $ft_cert $cert;
        $ft_cert->flush();
        $fn_cert = $ft_cert->filename();
    }

    my $openssl = $self->get_openssl_path();
    my $cmd_str = "$openssl x509 -inform DER -in $fn_cert ".
                  "-text -noout | grep 'CA Repository - URI:'";
    my ($repo_url) = `$cmd_str`;
    $repo_url =~ s/.*?URI://;
    $repo_url =~ s/\s*$//;

    return $repo_url;
}

sub get_manifest_url
{
    my ($self, $cert) = @_;

    my $ft_cert;
    my $fn_cert;
    if (-e $cert) {
        $fn_cert = $cert;
    } else {
        my $ft_cert = File::Temp->new();
        print $ft_cert $cert;
        $ft_cert->flush();
        $fn_cert = $ft_cert->filename();
    }

    my $openssl = $self->get_openssl_path();
    my $cmd_str = "$openssl x509 -inform DER -in $fn_cert ".
                  "-text -noout | grep 'URI.*\.mft'";
    my ($mft_url) = `$cmd_str`;
    $mft_url =~ s/.*?URI://;
    $mft_url =~ s/\s*$//;

    return $mft_url;
}

sub get_crl_serials
{
    my ($self, $crl) = @_;

    my $fn_crl;
    my $ft_crl = File::Temp->new();

    if (-e $crl) {
        $fn_crl = $crl;
    } else {
        print $ft_crl $crl;
        $ft_crl->flush();
        $fn_crl = $ft_crl->filename();
    }

    my $openssl = $self->get_openssl_path();
    my $cmd_str = "$openssl crl -inform DER -in $fn_crl ".
                  "-text -noout";
    my @lines = `$cmd_str`;
    chomp for @lines;

    my $in_revoked = 0;
    my @serials;
    for (my $i = 0; $i < @lines; $i++) {
        if (not $in_revoked) {
            if ($lines[$i] =~ /^Revoked Certificates/) {
                $in_revoked = 1;
            }
        } else {
            if ($lines[$i] =~ /^    Serial Number: (.*)$/) {
                push @serials, $1;
            } elsif ($lines[$i] =~ /^    Signature/) {
                last;
            }
        }
    }

    @serials = map { s/0*//; $_ } @serials;

    return \@serials;
}

sub get_serial
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->get_openssl_path();
    my $cmd_str = "$openssl x509 -in $fn_cert ".
                  "-text -noout";
    my @lines = `$cmd_str`;
    chomp for @lines;
    my $serial_line =
        first { /^        Serial Number:/ }
            @lines;
    my ($serial) = ($serial_line =~ /.*: \d+ \(0x(.*)\)/);
    return $serial;
}

sub is_inherit
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->get_openssl_path();
    my $cmd_str = "$openssl x509 -in $fn_cert ".
                  "-text -noout";
    my @lines = `$cmd_str`;
    chomp for @lines;
    my $data = join '', @lines;
    $data =~ s/\s+/ /g;
    if ($data =~ /sbgp-autonomousSysNum: critical Autonomous System Numbers: inherit sbgp-ipAddrBlock: critical IPv4: inherit IPv6: inherit/) {
        return 1;
    }
    return;
}

sub get_public_key
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->get_openssl_path();
    my $cmd_str = "$openssl x509 -in $fn_cert ".
                  "-pubkey -noout";
    my @lines = `$cmd_str`;
    chomp for @lines;
    return \@lines;
}

1;
