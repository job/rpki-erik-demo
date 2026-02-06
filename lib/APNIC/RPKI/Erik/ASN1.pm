package APNIC::RPKI::Erik::ASN1;

use warnings;
use strict;

use Convert::ASN1;
use DateTime;

use constant ID_SHA256 => '2.16.840.1.101.3.4.2.1';

use constant ERIK_ASN1 => q(
  GeneralName ::= CHOICE {
    uniformResourceIdentifier [6] IA5String }

  Digest ::= OCTET STRING

  AlgorithmIdentifier ::= SEQUENCE {
    algorithm      OBJECT IDENTIFIER,
    parameters     ANY DEFINED BY algorithm OPTIONAL }

  DigestAlgorithmIdentifier ::= AlgorithmIdentifier

  KeyIdentifier ::= OCTET STRING

  AccessDescription  ::=  SEQUENCE {
    accessMethod   OBJECT IDENTIFIER,
    accessLocation GeneralName }

  ErikIndex ::= SEQUENCE {
    version [0]    INTEGER OPTIONAL, -- DEFAULT 0,
    indexScope     IA5String,
    indexTime      GeneralizedTime,
    hashAlg        DigestAlgorithmIdentifier,
    partitionList  SEQUENCE OF PartitionRef }

  PartitionRef ::= SEQUENCE {
    hash           Digest,
    size           INTEGER }

  ErikPartition ::= SEQUENCE {
    version [0]    INTEGER OPTIONAL, -- DEFAULT 0,
    partitionTime  GeneralizedTime,
    hashAlg        DigestAlgorithmIdentifier,
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

  ContentInfoErikIndex ::= SEQUENCE {
    contentType    OBJECT IDENTIFIER,
    index          [0] EXPLICIT ErikIndex }
);

our $VERSION = "0.01";

sub get_parser
{
    my $parser = Convert::ASN1->new();
    $parser->configure(
        encoding => "DER",
        encode   => { time => "utctime" },
        decode   => { time => "utctime" },
    );
    my $res = $parser->prepare(ERIK_ASN1());
    if (not $res) {
        die $parser->error();
    }
    return $parser;
}

1;
