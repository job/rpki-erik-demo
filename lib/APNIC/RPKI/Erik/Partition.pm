package APNIC::RPKI::Erik::Partition;

use warnings;
use strict;

use Convert::ASN1;
use DateTime;

use constant ID_SHA256 => '2.16.840.1.101.3.4.2.1';

use constant ERIK_PARTITION_ASN1 => q(
  GeneralName ::= CHOICE {
    uniformResourceIdentifier [6] IA5String }

  Digest ::= OCTET STRING

  DigestAlgorithmIdentifier ::= OBJECT IDENTIFIER

  KeyIdentifier ::= OCTET STRING

  AccessDescription  ::=  SEQUENCE {
    accessMethod   OBJECT IDENTIFIER,
    accessLocation GeneralName }

  AlgorithmIdentifier ::= SEQUENCE {
    algorithm      OBJECT IDENTIFIER,
    parameters     ANY DEFINED BY algorithm OPTIONAL }

  ErikIndex ::= SEQUENCE {
    version [0]    INTEGER OPTIONAL, -- DEFAULT 0,
    indexScope     IA5String,
    indexTime      GeneralizedTime,
    -- Draft has DigestAlgorithmIdentifier, but rpkitouch uses
    -- AlgorithmIdentifier.
    -- hashAlg        DigestAlgorithmIdentifier,
    hashAlg        AlgorithmIdentifier,
    partitionList  SEQUENCE OF PartitionRef }

  PartitionRef ::= SEQUENCE {
    hash           Digest,
    size           INTEGER }

  ErikPartition ::= SEQUENCE {
    version [0]    INTEGER OPTIONAL, -- DEFAULT 0,
    partitionTime  GeneralizedTime,
    -- Draft has DigestAlgorithmIdentifier, but rpkitouch uses
    -- AlgorithmIdentifier.
    -- hashAlg        DigestAlgorithmIdentifier,
    hashAlg        AlgorithmIdentifier,
    manifestList   SEQUENCE OF ManifestRef }

  ManifestRef ::= SEQUENCE {
    hash           Digest,
    size           INTEGER, -- (1000..MAX),
    aki            KeyIdentifier,
    manifestNumber INTEGER, -- (0..MAX),
    thisUpdate     GeneralizedTime,
    locations      SEQUENCE OF AccessDescription }

  ContentInfoErikPartition ::= SEQUENCE {
    contentType    OBJECT IDENTIFIER,
    partition      [0] EXPLICIT ErikPartition }
);

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

    my $parser = Convert::ASN1->new();
    $parser->configure(
        encoding => "DER",
        encode   => { time => "utctime" },
        decode   => { time => "utctime" },
    );
    my $res = $parser->prepare(ERIK_PARTITION_ASN1());
    if (not $res) {
        die $parser->error();
    }
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

    my $partition = $data->{'partition'};
    $self->partition_time(DateTime->from_epoch(epoch => $partition->{'partitionTime'}));

    if ($partition->{'hashAlg'}->{'algorithm'} ne ID_SHA256()) {
        die "unexpected hashing algorithm in partition: ".
            $data->{'hashAlg'};
    }

    my @manifest_list;
    for my $ml (@{$partition->{'manifestList'}}) {
        push @manifest_list, {
            hash     => $ml->{'hash'},
            size     => $ml->{'size'},
            aki     => $ml->{'aki'},
            manifest_number     => $ml->{'manifestNumber'},
            this_update => DateTime->from_epoch(epoch => $ml->{'thisUpdate'}),
            locations => $ml->{'locations'}
        };
    }
    $self->manifest_list(@manifest_list);

    return 1;
}

sub encode
{
    my ($self) = @_;

    my $data = {
        contentType => ID_SHA256(),
        partition => {
            partitionTime => $self->partition_time()->epoch(),
            hashAlg => {
                algorithm => ID_SHA256(),
            },
            manifestList => [
                map { +{
                    hash => $_->{'hash'},
                    size => $_->{'size'},
                    aki  => $_->{'aki'},
                    manifestNumber => $_->{'manifest_number'},
                    thisUpdate => $_->{'this_update'}->epoch(),
                    locations => [ map { +{
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
    return $enc_data;
}

1;
