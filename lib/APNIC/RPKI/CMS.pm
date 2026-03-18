package APNIC::RPKI::CMS;

use warnings;
use strict;

use Convert::ASN1;

use constant CMS_ASN1 => q(
   -- from rfc5652 section 12.1

   ContentInfo ::= SEQUENCE {
     contentType ContentType,
     content [0] EXPLICIT ANY DEFINED BY contentType }

   ContentType ::= OBJECT IDENTIFIER

   SignedData ::= SEQUENCE {
     version CMSVersion,
     digestAlgorithms DigestAlgorithmIdentifiers,
     encapContentInfo EncapsulatedContentInfo,
     certificates [0] IMPLICIT CertificateSet OPTIONAL,
     crls         [1] IMPLICIT RevocationInfoChoices OPTIONAL,
     signers      SET OF SignerInfo }

   CMSVersion ::= INTEGER

   DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

   DigestAlgorithmIdentifier ::= AlgorithmIdentifier

   SignatureAlgorithmIdentifier ::= AlgorithmIdentifier

   AlgorithmIdentifier  ::=  SEQUENCE  {
     oid                     OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY oid OPTIONAL  }
                                -- contains a value of the type
                                -- registered for use with the
                                -- algorithm object identifier value

   EncapsulatedContentInfo ::= SEQUENCE {
     eContentType ContentType,
     eContent [0] EXPLICIT OCTET STRING OPTIONAL }

   CertificateSet ::= SET OF ANY

   RevocationInfoChoices ::= SET OF ANY

   SignerInfo ::= SEQUENCE {
     version CMSVersion,
     signerIdentifier SignerIdentifier,
     digestAlgorithm DigestAlgorithmIdentifier,
     signedAttrs   [0] IMPLICIT Attributes OPTIONAL,
     signatureAlgorithm SignatureAlgorithmIdentifier,
     signature SignatureValue,
     unsignedAttrs [1] IMPLICIT Attributes OPTIONAL }

   SignerIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier [0] SubjectKeyIdentifier }

   IssuerAndSerialNumber ::= SEQUENCE {
     issuer IssuerName,
     serialNumber CertificateSerialNumber }

   SignatureValue ::= OCTET STRING

   IssuerName  ::=  OCTET STRING

   CertificateSerialNumber  ::=  INTEGER

   SubjectKeyIdentifier ::= OCTET STRING

   Attributes ::= SET OF Attribute

   Attribute ::= SEQUENCE {
     oid OBJECT IDENTIFIER,
     values SET OF ANY }

   ContentTypeAttributeValue ::= OBJECT IDENTIFIER

   SigningTime  ::= CHOICE {
      utcTime UTCTime,
      generalTime GeneralizedTime }

   BinaryTime ::= INTEGER
   BinarySigningTime ::= BinaryTime

   cRLDistributionPoints  ::= SEQUENCE OF DistributionPoint

   DistributionPoint ::= SEQUENCE {
      distributionPoint       [0]     DistributionPointName OPTIONAL,
      reasons                 [1]     ReasonFlags OPTIONAL,
      cRLIssuer               [2]     GeneralNames OPTIONAL }

   DistributionPointName ::= CHOICE {
      fullName                [0]     GeneralNames,
      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

   ReasonFlags ::= BIT STRING

   RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

   AttributeTypeAndValue ::= SEQUENCE {
      type               OBJECT IDENTIFIER,
      value              ANY }

   GeneralNames ::= SEQUENCE OF GeneralName

   GeneralName ::= CHOICE {
      otherName                       [0]     OtherName,
      rfc822Name                      [1]     IA5String,
      dNSName                         [2]     IA5String,
      x400Address                     [3]     ANY, --ORAddress,
      directoryName                   [4]     Name,
      ediPartyName                    [5]     EDIPartyName,
      uniformResourceIdentifier       [6]     IA5String,
      iPAddress                       [7]     OCTET STRING,
      registeredID                    [8]     OBJECT IDENTIFIER }

   OtherName ::= SEQUENCE {
      type-id    OBJECT IDENTIFIER,
      value      [0] EXPLICIT ANY DEFINED BY type-id }

   EDIPartyName ::= SEQUENCE {
      nameAssigner            [0]     DirectoryString OPTIONAL,
      partyName               [1]     DirectoryString }

   Name ::= CHOICE { rdnSequence RDNSequence }

   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

   DirectoryString ::= CHOICE {
      teletexString           TeletexString,
      printableString         PrintableString,
      bmpString               BMPString,
      universalString         UniversalString,
      utf8String              UTF8String,
      ia5String               IA5String }
);

use base qw(Class::Accessor);
APNIC::RPKI::CMS->mk_accessors(qw(
    payload
));

my $parser_ci;
my $parser_sd;

sub new
{
    my ($class) = @_;

    if (not $parser_ci) {
        my $parser = Convert::ASN1->new();
        $parser->configure(
            encoding => "DER",
            encode   => { time => "utctime" },
            decode   => { time => "utctime" }
        );
        my $res = $parser->prepare(CMS_ASN1());
        if (not $res) {
            die $parser->error();
        }
        $parser_ci = $parser->find('ContentInfo');
        $parser_sd = $parser->find('SignedData');
    }

    my $self = { parser_ci => $parser_ci,
                 parser_sd => $parser_sd };
    bless $self, $class;
    return $self;
}

sub decode
{
    my ($self, $cms) = @_;

    my $parser_ci = $self->{'parser_ci'};
    my $data = $parser_ci->decode($cms);
    if (not $data) {
        die $parser_ci->error();
    }
    my $parser_sd = $self->{'parser_sd'};
    my $sd = $parser_sd->decode($data->{'content'});
    if (not $sd) {
        die $parser_sd->error();
    }

    $self->payload({ content_type => $data->{'contentType'},
                     content      => $sd });
    return 1;
}

sub type
{
    my ($self) = @_;

    my $eci = $self->payload()
                   ->{'content'}
                   ->{'encapContentInfo'};
    my $ect = $eci->{'eContentType'};
    if ($ect eq '1.2.840.113549.1.9.16.1.24') {
        return 'roa';
    } elsif ($ect eq '1.2.840.113549.1.9.16.1.26') {
        return 'mft';
    } else {
        die "unknown content type: '$ect'";
    }
}

1;
