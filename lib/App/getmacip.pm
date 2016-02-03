package App::getmacip;

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

}

1;
