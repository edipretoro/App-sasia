package App::sasia;

use strict;
use warnings;
use Modern::Perl '2015';

use Moo;
use MooX::Options;

use Nmap::Scanner;
use YAML qw(LoadFile DumpFile Dump);
use Template;

our %machines;

has machines => (
  is => 'rw',
  isa => sub { die "$_[0] is not an hashref" unless ref($_[0]) eq 'HASH' },
  default => sub { return {} },
);

option ip_range => (
  is => 'ro',
  format => 's',
  short => 'i|ip',
  required => 1,
  default => sub { return '192.168.1.0/24' },
  doc => 'The range of IP adresses to scan.'
);

option filter_filename => (
  is => 'ro',
  format => 's',
  required => 0,
  short => 'f|filter',
  doc => 'A YAML file containing information to filter and aggregate the scanning information.'
);

option template_filename => (
  is => 'ro',
  format => 's',
  required => 0,
  short => 't|template',
  doc => 'A TT template to display the information.'
);

sub run {
  my ( $self ) = @_;

  $self->_is_root();
  $self->_scan();
  $self->_filter();
  $self->_display();
}

sub _is_root {
  die "$0: You probably need to be root to get the informations needed.\n" unless $> == 0;
}

sub _scan {
  my ( $self ) = @_;

  my $scanner = Nmap::Scanner->new();
  $scanner->register_scan_started_event( \&_scanning );
  $scanner->scan( ' -sn ' . $self->ip_range() );
}

sub _filter {
  my ( $self ) = @_;

  my $machines = $self->machines();

  if ($self->filter_filename) {
    die "Couldn't find the filter filename: ", $self->filter_filename, "\n" unless -e $self->filter_filename;
    my $filter = LoadFile( $self->filter_filename() );
    foreach my $mac (keys %{$filter}) {
      $machines->{fc $mac} = $filter->{$mac};
      $machines->{fc $mac}{ipv4} = $machines{fc $mac};
    }
  } else {
    $machines = \%machines;
  }

  $self->machines( $machines );
}

sub _display {
  my ( $self ) = @_;

  if ($self->template_filename) {
  } else {
    print Dump( $self->machines );
  }
}

sub _scanning {
  my ( $self, $host ) = @_;

  my @addresses = $host->addresses();
  my $macaddr;
  my $ipaddr;

  foreach my $address ( @addresses ) {
    if ($address->addrtype() eq 'mac') {
      $macaddr = $address->addr();
    } elsif ($address->addrtype eq 'ipv4') {
      $ipaddr = $address->addr();
    }
  }
  $machines{fc $macaddr} = $ipaddr if defined( $macaddr );
}

1;
