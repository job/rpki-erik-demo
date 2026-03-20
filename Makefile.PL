use strict;
use warnings;

use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

my $output = WriteMakefile(
    NAME           => 'APNIC::RPKI::Manifest',
    AUTHOR         => 'Software <software@apnic.net>',
    LICENSE        => 'bsd',
    VERSION_FROM   => 'lib/APNIC/RPKI/Manifest.pm',
    META_MERGE     => {
        resources => {
            repository => 'https://github.com/APNIC-net/rpki-erik-demo'
        }
    },
    EXE_FILES      => [
        'bin/erik-client',
        'bin/erik-server',
        'bin/erik-updater',
        'bin/erik-partitioner',
    ],
    PREREQ_PM      => {
        'Test::More'                 => 0,
        'File::Slurp'                => 0,
        'IO::Socket'                 => 0,
        'JSON::XS'                   => 0,
        'Net::IP::XS'                => 0,
        'IO::Select'                 => 0,
        'IO::Socket::SSL'            => 0,
        'Net::EmptyPort'             => 0,
        'Class::Accessor'            => 0,
        'Convert::ASN1'              => 0,
        'File::Path'                 => 0,
        'HTTP::Daemon'               => 0,
        'IO::Compress::Gzip'         => 0,
        'IO::Uncompress::Gunzip'     => 0,
        'MIME::Base64'               => 0,
        'Net::CIDR::Set'             => 0,
        'Set::IntSpan'               => 0,
        'IO::Async::Loop'            => 0,
        'IO::Async::SSL'             => 0,
        'IO::Async::Timer::Periodic' => 0,
        'Net::Async::HTTP'           => 0,
    }
);

1;
