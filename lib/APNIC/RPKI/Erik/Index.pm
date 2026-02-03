package APNIC::RPKI::Erik::Index;

use warnings;
use strict;

use APNIC::RPKI::Erik::ASN1;

use Convert::ASN1;
use DateTime;

use constant ID_SHA256 => '2.16.840.1.101.3.4.2.1';
use constant CT_IN     => '1.2.840.113549.1.9.16.1.55';

use base qw(Class::Accessor);
APNIC::RPKI::Erik::Index->mk_accessors(qw(
    version
    index_scope
    index_time
    hash_algorithm
    partition_list
));

our $VERSION = "0.01";

sub new
{
    my ($class) = @_;

    my $parser = APNIC::RPKI::Erik::ASN1::get_parser();
    $parser = $parser->find('ContentInfoErikIndex');
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
    if ($ct ne CT_IN()) {
        die "Unexpected content type '$ct' (expected '".CT_IN()."')";
    }

    my $index = $data->{'index'};
    $self->index_scope($index->{'indexScope'});
    $self->index_time(DateTime->from_epoch(epoch => $index->{'indexTime'}));

    if ($index->{'hashAlg'}->{'algorithm'} ne ID_SHA256()) {
        die "unexpected hashing algorithm in partition: ".
            $data->{'hashAlg'};
    }

    my @partition_list;
    for my $ml (@{$index->{'partitionList'}}) {
        push @partition_list, {
            hash => unpack('H*', $ml->{'hash'}),
            size => $ml->{'size'},
        };
    }
    $self->partition_list(\@partition_list);

    return 1;
}

sub encode
{
    my ($self) = @_;

    my $data = {
        contentType => CT_IN(),
        index => {
            indexScope => $self->index_scope(),
            indexTime => $self->index_time()->epoch(),
            hashAlg => {
                algorithm => ID_SHA256(),
            },
            partitionList => [
                map { +{
                    hash => pack('H*', $_->{'hash'}),
                    size => $_->{'size'},
                } } (@{$self->partition_list()})
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

1;
