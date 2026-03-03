package APNIC::RPKI::Erik::Server;

use warnings;
use strict;

use APNIC::RPKI::Utils qw(dprint);

use File::Slurp qw(read_file);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);

sub new
{
    my ($class, $port, $httpd_dir) = @_;

    my $self = {
        port      => $port,
        httpd_dir => $httpd_dir,
    };

    my $d = HTTP::Daemon->new(
        LocalPort => $self->{"port"},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $d) {
        die "Unable to start server: $!";
    }

    $self->{"d"} = $d;
    $self->{"port"} = $d->sockport();
    $self->{'url_base'} = 'http://localhost:'.$self->{'port'};

    bless $self, $class;
    return $self;
}

sub run
{
    my ($self) = @_;

    my $d = $self->{"d"};
    while (my $c = $d->accept()) {
        while (my $r = $c->get_request()) {
            dprint("Beginning request handling");
            chdir $self->{"httpd_dir"} or die $!;
            my $metadata = read_file(".well-known/erik/metadata");
            my $md = decode_json($metadata);
            my $cc = $md->{'char_count'};
            my $dc = $md->{'dir_count'};

            my $method = $r->method();
            my $path = $r->uri()->path();
            dprint("Received request: '$method' '$path'");
            $path =~ s/^\///;

            my ($remaining_fn) = ($path =~ /^.well-known\/ni\/sha-256\/(.*)$/);
            if ($remaining_fn) {
                my $current_dir = ".well-known/ni/sha-256";
                while ($dc--) {
                    my ($next_chars) = ($remaining_fn =~ /^(.{$cc})/);
                    $remaining_fn =~ s/^.{$cc}//;
                    if (not $remaining_fn) {
                        die "Too many characters taken from filename";
                    }
                    $current_dir = "$current_dir/$next_chars";
                }
                $path = "$current_dir/$remaining_fn";
            }

            my $res;
            eval {
                if ($method eq 'GET') {
                    $c->send_file_response($path); 
                }
            };
            if (my $error = $@) {
                warn $error;
                $res = HTTP::Response->new(HTTP_INTERNAL_SERVER_ERROR);
            } elsif (not $res) {
                $res = HTTP::Response->new(HTTP_NOT_FOUND);
            }
            $c->send_response($res);
        }
    }

    return 1;
}

1;
