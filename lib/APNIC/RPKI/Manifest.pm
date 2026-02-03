package APNIC::RPKI::Manifest;

use warnings;
use strict;

use Convert::ASN1;
use DateTime;

use constant ID_SMIME           => '1.2.840.113549.1.9.16';
use constant ID_CT              => ID_SMIME . '.1';
use constant ID_CT_RPKIMANIFEST => ID_CT . '.26';

use constant ID_SHA256 => '2.16.840.1.101.3.4.2.1';

use constant MANIFEST_VERSION_DEFAULT => 0;

use constant MANIFEST_ASN1 => q(
  Manifest ::= SEQUENCE {
    version     [0] INTEGER OPTIONAL, -- DEFAULT 0,
    manifestNumber  INTEGER,
    thisUpdate      GeneralizedTime,
    nextUpdate      GeneralizedTime,
    fileHashAlg     OBJECT IDENTIFIER,
    fileList        SEQUENCE OF FileAndHash
  }

  FileAndHash ::=     SEQUENCE {
    file            IA5String,
    hash            BIT STRING
  }
);

use base qw(Class::Accessor);
APNIC::RPKI::Manifest->mk_accessors(qw(
    version
    manifest_number
    this_update
    next_update
    files
));

our $VERSION = "0.01";

sub new
{
    my ($class) = @_;

    my $parser = Convert::ASN1->new();
    $parser->configure(
        encoding => "DER",
        encode   => { time => "utctime" },
        decode   => { time => "utctime" }
    );
    my $res = $parser->prepare(MANIFEST_ASN1());
    if (not $res) {
        die $parser->error();
    }
    $parser = $parser->find('Manifest');

    my $self = { parser => $parser };
    bless $self, $class;
    return $self;
}

sub decode
{
    my ($self, $mft) = @_;

    my $parser = $self->{'parser'};
    my $data = $parser->decode($mft);
    if (not $data) {
        die $parser->error();
    }

    $self->manifest_number($data->{'manifest_number'});
    $self->this_update(DateTime->from_epoch(epoch => $data->{'thisUpdate'}));
    $self->next_update(DateTime->from_epoch(epoch => $data->{'nextUpdate'}));

    if ($data->{'fileHashAlg'} ne ID_SHA256()) {
        die "unexpected hashing algorithm in manifest: ".
            $data->{'fileHashAlg'};
    }

    my @files;
    for my $file (@{$data->{'fileList'}}) {
        if ($file->{'hash'}->[1] != 256) {
            die "unexpected hash value: ".
                $file->{'hash'}->[1];
        }
        push @files, {
            filename => $file->{'file'},
            hash     => unpack('H*', $file->{'hash'}->[0])
        };
    }
    $self->files(\@files);

    return 1;
}

1;
