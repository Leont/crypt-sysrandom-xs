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

This will fetch a string of C<$count> random bytes containing cryptographically secure random data.

=head1 BACKENDS

At build-time, it will try the following backends in order:

=over 4

=item * getrandom

This backend is available on Linux, FreeBSD and Solaris

=item * arc4random

This interface is supported on most BSDs and Mac.

=item * BCryptGenRandom

This backend is available on Windows (Vista and newer)

=item * rdrand64

This is available on C<x86_64> architectures using most compilers.

=item * rdrand32

This is available on C<x86_64> and C<x86> architectures using most compilers.

=back
