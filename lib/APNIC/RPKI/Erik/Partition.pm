package APNIC::RPKI::Erik::Partition;

use warnings;
use strict;

use APNIC::RPKI::Erik::ASN1;

use Convert::ASN1;
use DateTime;
use JSON::XS qw(encode_json);

use constant ID_SHA256 => '2.16.840.1.101.3.4.2.1';
use constant CT_EP     => '1.2.840.113549.1.9.16.1.56';

use base qw(Class::Accessor);
APNIC::RPKI::Erik::Partition->mk_accessors(qw(
    version
    partition_time
    hash_algorithm
    manifest_list
));

our $VERSION = "0.01";

sub new
{
    my ($class) = @_;

    my $parser = APNIC::RPKI::Erik::ASN1::get_parser();
    $parser = $parser->find('ContentInfoErikPartition');
    my $self = { parser => $parser };
    bless $self, $class;
    return $self;
}

sub decode
{
    my ($self, $ep) = @_;

    my $parser = $self->{'parser'};
    my $data = $parser->decode($ep);
    if (not $data) {
        die $parser->error();
    }

    my $ct = $data->{'contentType'};
    if ($ct ne CT_EP()) {
        die "Unexpected content type '$ct' (expected '".CT_EP()."')";
    }

    my $partition = $data->{'partition'};
    $self->partition_time(DateTime->from_epoch(epoch => $partition->{'partitionTime'}));

    if ($partition->{'hashAlg'}->{'algorithm'} ne ID_SHA256()) {
        die "unexpected hashing algorithm in partition: ".
            $data->{'hashAlg'};
    }

    my @manifest_list;
    for my $ml (@{$partition->{'manifestList'}}) {
        push @manifest_list, {
            hash            => unpack('H*', $ml->{'hash'}),
            size            => $ml->{'size'},
            aki             => unpack('H*', $ml->{'aki'}),
            manifest_number => $ml->{'manifestNumber'},
            this_update     => DateTime->from_epoch(epoch => $ml->{'thisUpdate'}),
            locations       => [ map {
                $_->{'accessLocation'}->{'uniformResourceIdentifier'}
            } @{$ml->{'locations'}} ]
        };
    }
    $self->manifest_list(\@manifest_list);

    return 1;
}

sub encode
{
    my ($self) = @_;

    my $data = {
        contentType => CT_EP(),
        partition => {
            partitionTime => $self->partition_time()->epoch(),
            hashAlg => {
                algorithm => ID_SHA256(),
            },
            manifestList => [
                map { +{
                    hash           => pack('H*', $_->{'hash'}),
                    size           => $_->{'size'},
                    aki            => pack('H*', $_->{'aki'}),
                    manifestNumber => $_->{'manifest_number'},
                    thisUpdate     => $_->{'this_update'}->epoch(),
                    locations      => [ map { +{
                        accessMethod   => "1.3.6.1.5.5.7.48.11",
                        accessLocation => {
                            uniformResourceIdentifier => $_,
                        }
                    } } @{$_->{'locations'}} ]
                } } (@{$self->manifest_list()})
            ]
        }
    };

    my $parser = $self->{'parser'};
    my $enc_data = $parser->encode($data);
    if (not $enc_data) {
        die $parser->error();
    }
    return $enc_data;
}

sub to_json
{
    my ($self) = @_;

    my %data = (
        version        => $self->version(),
        partition_time => $self->partition_time()->strftime('%F %T'),
        hash_algorithm => "sha256",
        manifest_list  => $self->manifest_list()
    );
    for my $ml (@{$data{'manifest_list'}}) {
        $ml->{'this_update'} = $ml->{'this_update'}->strftime('%F %T');
    }

    return encode_json(\%data);
}

1;
