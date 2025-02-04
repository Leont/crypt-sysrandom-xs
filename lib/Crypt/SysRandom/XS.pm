package Crypt::SysRandom::XS;

use strict;
use warnings;

use XSLoader;

XSLoader::load(__PACKAGE__, __PACKAGE__->VERSION);

use Exporter 'import';
our @EXPORT_OK = 'random_bytes';

1;

# ABSTRACT: Perl interface to system randomness, XS version

=head1 SYNOPSIS

 use Crypt::SysRandom::XS 'random_bytes';
 my $random = random_bytes(16);

=head1 DESCRIPTION

This module uses whatever C interface is available to procure cryptographically random data from the system.

=func random_bytes($count)

This will fetch a string of C<$count> random bytes containing cryptographically secure random date.
