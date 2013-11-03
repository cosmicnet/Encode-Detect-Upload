package Encode::Detect::Upload;

=head1 NAME

Encode::Detect::Upload - Attempt to guess users locale encoding from IP, HTTP_ACCEPT_LANGUAGE and HTTP_USER_AGENT

=head1 SYNOPSIS

    use Encode::Detect::Upload;
    my $detector = new Encode::Detect::Upload;
    # Feelin lucky!
    my $charset = $detector->detect();
    # More sensible
    my ( $charset_list, $meta ) = $detector->detect();

=head1 DESCRIPTION

Dealing with input from globally disperse users can be a real pain. Although when
setting web forms to utf-8 browsers will often do the right thing, in some
instances, such as text file uploads, you are stuck will trying to figure out
the files charset encoding. L<Encode::Detect::Detector> uses Mozilla's universal
charset detector, which works great most of the time. But when it doesn't your
stuck with asking the user, a user that all to often these days has a very low
technical ability, and likely doesn't know what a charset it.

In my experience with dealing with such user uploads, the charset of the file
usually relates to the users OS, location and language settings. Although it's
true that the file could have any encoding, the file could have been created on
a different machine, with a different locale to the one that is doing the upload.
But the use of this modules techniques along with that of
L<Encode::Detect::Detector> more cases can be handled correctly. Methods for
helping the user chose encoding are also provided.

=cut

use utf8;
use strict;
use warnings;
use Carp;

use Encode::Detect::Upload::Data;
use Encode;

my $country_lang = \%Encode::Detect::Upload::Data::country_lang;
my $lang_charset = \%Encode::Detect::Upload::Data::lang_charset;

# Try to load some other modules
my $has_ipcountry = 1;
eval 'use IP::Country';
$has_ipcountry = 0 if $@;

my $has_geoip = 1;
eval 'use Geo::IP';
$has_geoip = 0 if $@;

my $has_detect = 1;
eval 'use Encode::Detect::Detector qw()';
$has_detect = 0 if $@;


=head2 Methods

=over 12

=item C<new>

Returns a new detection object.

=cut

sub new {
    my $class = shift;
    my %config = (
        die_on_missing => 1,
    );
    my $param;
    if ( @_ == 1 && ref $_[0] eq 'HASH' ) {
        $param = $_[0];
    }
    elsif ( @_ % 2 == 0 ) {
        $param = { @_ };
    }
    else {
        croak( "Invalid parameters, must be either single hashref or key=>value pairs" );
    }
    if ( $param ) {
        %config = (
            %config,
            %$param,
        );
    }
    my $self = bless \%config, $class;
    return $self;
}


=item C<get_os>

Requires the HTTP_USER_AGENT string which can be passed, otherwise it attempts
to use C<$ENV{HTTP_USER_AGENT}>. Dies if it cannot find a user_agent string.
Returns either "Windows", "Linux", "Macintosh" or undefined if no match was
made.

=cut

sub get_os {
    my $self = shift;
    my $agent = shift;
    $agent ||= $ENV{HTTP_USER_AGENT};
    croak( 'No USER_AGENT string passed, and $ENV{HTTP_USER_AGENT} is empty' ) unless $agent || $self->{die_on_missing} == 0;
    # Basic regexps for matching
    return 'Windows' if $agent =~ /Windows/;
    return 'Macintosh' if $agent =~ /\W(Macintosh|Mac)\W/;
    return 'Linux' if $agent =~ /Linux/;
    return undef;
}


=item C<get_country>

Requires the users IP which can be passed, otherwise it attempts to use
C<$ENV{REMOTE_ADDR}>. Returns the ISO 2 character country code.

=cut

sub get_country {
    my $self = shift;
    croak( 'Could not load IP::Country or Geo::IP' ) unless $has_ipcountry || $has_geoip;
    my $ip = shift;
    $ip ||= $ENV{REMOTE_ADDR};
    croak( 'No IP passed, and $ENV{REMOTE_ADDR} is empty' ) unless $ip;
    my $ip_match = qr/^(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])$/o;
    croak( "$ip is not a valid IP" ) unless $ip =~ $ip_match;

    # Use the available IP -> Country DB
    if ( $has_ipcountry ) {
        my $reg = IP::Country->new();
        my $country = $reg->inet_atocc($ip);
        $country = undef if $country = '**';
        return lc $country;
    }
    if ( $has_geoip ) {
        my $gi;
        my $data_file = shift;
        if ( $data_file ) {
            die( "Geo::IP data file $data_file does not exist" ) unless -e $data_file;
            $gi = Geo::IP->new( $data_file, 0 ); # 0 = GEOIP_STANDARD
        }
        else {
            $gi = Geo::IP->new( 0 );
        }
        return lc $gi->country_code_by_addr( $ip );
    }
}


=item C<get_country_lang>

Requires the ISO 2 character country code. Returns either a single language code
or list of language codes depending on calling context.

=cut

sub get_country_lang {
    my $self = shift;
    my $country = lc shift;
    croak( 'No country passed' ) unless defined $country;
    return undef unless ref $country_lang->{$country};
    if ( wantarray ) {
        return @{ $country_lang->{$country}->{languages} };
    }
    else {
        return $country_lang->{$country}->{languages}->[0];
    }
}


=item C<get_country_name>

Requires the ISO 2 character country code. Returns the countries name.

=cut

sub get_country_name {
    my $self = shift;
    my $country = lc shift;
    croak( 'No country passed' ) unless defined $country;
    return $country_lang->{$country}->{name};
}


=item C<get_accept_lang>

Requires the HTTP_ACCEPT_LANGUAGE string from the browser, otherwise it attempts
to use C<$ENV{HTTP_ACCEPT_LANGUAGE}>. Returns either a single language code or
list of language codes depending on calling context.

=cut

sub get_accept_lang {
    my $self = shift;
    my $accept = shift;
    $accept ||= $ENV{HTTP_ACCEPT_LANGUAGE};
    croak( 'No ACCEPT_LANGUAGE string passed, and $ENV{HTTP_ACCEPT_LANGUAGE} is empty' ) unless $accept || $self->{die_on_missing} == 0;
    # We are going to ignore q and assume the order is accurate... might not be the best policy
    my @langs;
    my %seen;
    foreach my $language ( split(/ *, */, $accept) ) {
        my ( $lang, $q ) = split(/ *; */, $language);
        $lang = lc $lang;
        if ( wantarray ) {
            next if $seen{$lang}; # filter out any duplicates
            push( @langs, $lang );
            $seen{$lang}++;
        }
        else {
            return $lang;
        }
    }
    return @langs;
}


=item C<get_lang_name>

Requires the ISO 2 character language code (sometimes 3 character for when a 2
character doesn't exist). Returns the languages name.

=cut

sub get_lang_name {
    my $self = shift;
    my $lang = lc shift;
    croak( 'No language passed' ) unless defined $lang;
    return undef unless ref $lang_charset->{$lang};
    return $lang_charset->{$lang}->{name};
}


=item C<get_lang_list>

Requires the ISO 2 character language code (sometimes 3 character for when a 2
character doesn't exist). Returns a list of related language codes.

=cut

sub get_lang_list {
    my $self = shift;
    my $lang = lc shift;
    croak( 'No language passed' ) unless defined $lang;
    my @lang_list = ($lang);
    my %lang_seen = ( $lang => 1 );

    # Check if the inital lang is a cyrl/latn version
    my %latncryl = ( latn => 'cyrl', cyrl => 'latn' );
    if ( $lang =~ /^(.+)-(cyrl|latn)$/ ) {
        if ( $lang_charset->{"$1-$latncryl{$2}"} ) {
            push( @lang_list, "$1-$latncryl{$2}" );
            $lang_seen{"$1-$latncryl{$2}"}++;
        }
        $lang = $1;
    }
    else {
        # Check for cyrl/latn versions
        foreach my $chars ( qw( latn cyrl ) ) {
            if ( $lang_charset->{"$lang-$chars"} && ! $lang_seen{"$lang-$chars"} ) {
                push( @lang_list, "$lang-$chars" );
                $lang_seen{"$lang-$chars"}++;
            }
        }
    }
    # Check for general language
    if ( $lang =~ /^(.+)-/) {
        $lang = $1;
        if ( $lang_charset->{$lang} ) {
            push( @lang_list, $lang );
            $lang_seen{$lang}++;
        }
        # Check for cyrl/latn versions
        foreach my $chars ( qw( latn cyrl ) ) {
            if ( $lang_charset->{"$lang-$chars"} && ! $lang_seen{"$lang-$chars"} ) {
                push( @lang_list, "$lang-$chars" );
                $lang_seen{"$lang-$chars"}++;
            }
        }
    }

    return @lang_list;
}


=item C<get_lang_charset>

Requires the language code and os (when called in scalar context). Returns
either the charset for that os, or list of charsets ordered by likeliness,
depending on calling context. Likeliness order of Windows, Macintosh, Linux.

=cut

sub get_lang_charset {
    my $self = shift;
    my $lang = lc shift;
    my $os = lc shift;
    croak( 'No language passed' ) unless $lang;
    if ( wantarray ) {
        return () unless ref $lang_charset->{$lang};
        my @charsets;
        @charsets = ( $lang_charset->{$lang}->{$os} ) if $os;
        foreach my $osleft ( qw( windows macintosh linux ) ) {
            next if $osleft eq $os;
            push( @charsets, $lang_charset->{$lang}->{$osleft} );
        }
        return @charsets;
    }
    else {
        return undef unless ref $lang_charset->{$lang};
        croak( "OS $os not recognised" ) unless $os =~ /^(windows|linux|macintosh)$/;
        return $lang_charset->{$lang}->{$os};
    }
}


=item C<get_words>

Requires a sample text string and a charset, optionally the number of words to
try to match (default 10). Returns a list of words that contain non-ASCII
characters.

=cut

sub get_words {
    my $self = shift;
    my $text = shift;
    my $max = shift;
    $max ||= 10;
    croak( 'No sample text passed' ) unless $text;
    my ( @words, %words );
    while ( $text =~ /([\w\x80-\xff]*[\x80-\xff][\w\x80-\xff]*)/g ) {
        unless ( $words{$1} ) {
            push( @words, $1 );
            $words{$1}++;
        }
        last if @words > 9;
    }#while
    return @words;
}


=item C<detect>

Requires a sample text string. Can optionally be passed the number of words to
try to match (default 10), the users IP, the users OS, the user_agent string,
the language code(S), the accept_language string, whether linux charsets should
be included, and for advanced use you can adjust the way languages and charsets
are ranked. Returns either a single charset (in scalar context) or a list of
charsets ordered by most likely with associated meta data. If
L<Encode::Detect::Detector> is available it's guess is used to improve accuracy.

For discussion of ranking heuristics and how to adjust them, see the section below.

    # I'm feeling lucky
    my $charset = $detector->detect();

    # I'm feeling realistic
    my ( $charset_list, $charset_meta ) = $detector->detect( text => '...' );

    # Data structure example
    $charset_list = [ 'x-mac-cyrillic', 'x-mac-ce', 'windows-1251', 'x-mac-ukrainian'... ];
    $charset_meta = {
        charsets => {
            'x-mac-cyrillic' => {
                pos => 1, # Ranking position
                words => [ 'Здравствуй', ... ], # Sample word list
                lang => [ 'ru', ... ], # Language tags that led to this charset
            },
            'x-mac-ce' => {
                pos => 2,
                words => [ 'ášūŗ‚ŮÚ‚ůť', ... ],
                lang => [ 'sr', ... ],
            },
            'windows-1251' => {
                pos => 3,
                words => [ '‡дравствуй', ... ],
                lang => [ 'ru', ... ],
                mozilla => 1, # In this example mozilla guessed wrong
            },
            ...
        },
        lang => {
            ru => {
                name    => 'Russian', # Language name
                both    => 1, # Matched from both country and accept_lang
                country => 1, # Matched from country (IP)
                accept  => 1, # Matched from accept_lang
                pos     => 1, # Ranking position
            },
            ...
        },
        country  => {
            name => 'Russia',
            tag  => 'ru',
        },
        error => [ 'utf-8', ... ], # Text wouldn't parse as utf-8
    }

=cut

sub detect {
    my $self = shift;
    my $param;
    if ( @_ == 1 && ref $_[0] eq 'HASH' ) {
        $param = $_[0];
    }
    elsif ( @_ % 2 == 0 ) {
        $param = { @_ };
    }
    else {
        croak( "Invalid parameters, must be either single hashref or key=>value pairs" );
    }
    # TODO(LH) Maybe some param name validation
    my %conf = (
        words       => 10,
        ip          => $ENV{REMOTE_ADDR},
        user_agent  => $ENV{HTTP_USER_AGENT},
        accept_lang => $ENV{HTTP_ACCEPT_LANGUAGE},
        inc_linux   => 0,
        %$param,
    );

    my %rank = (
        lang => {
            start  => 'AC',
            repeat => 'AC',
        },
        lang_both => 1,
        char => {
            windows => {
                start  => 'WW',
                repeat => 'WML',
            },
            macintosh => {
                start  => 'M',
                repeat => 'MWL',
            },
            linux => {
                start  => 'LWM',
                repeat => 'LWM',
            },
        },
        mozilla_move => 1,
        mozilla_insert => 3,
    );
    if ( $conf{ranking} ) {
        %rank = %{ $conf{ranking} };
        # Validate ranking sequences
        croak( 'Missing language ranking sequence' ) unless $rank{lang}->{repeat};
        foreach my $os ( qw( windows macintosh linux ) ) {
            croak( 'Missing ' . ucfirst $os . ' charset ranking sequence' ) unless $rank{char}->{$os}->{repeat};
        }
    }

    # Get the OS
    unless ( $conf{os} ) {
        $conf{os} = $self->get_os( $conf{os} );
    }
    # Default to windows if we still don't have an OS
    $conf{os} = 'windows' unless $conf{os};
    $conf{os} = lc $conf{os};
    # OS of linux implies inc_linux
    $conf{inc_linux} = 1 if $conf{os} eq 'linux';

    # Get the list of language tags
    my %country_meta;
    my %lang_meta;
    if ( $conf{lang} ) {
        $conf{lang} = [ $conf{lang} ] unless ref $conf{lang};
        $conf{lang} = [ map { lc $_ } @{ $conf{lang} } ];
    }
    else {
        ## Get language list from conf with meta data
        # Start with country list
        my @country_list;
        if ( $conf{country} ) {
            @country_list = ref $conf{country} ? @{ $conf{country} } : ( $conf{country} );
            @country_list = map { lc $_ } @country_list;
        }
        else {
            # See if we have IP's to lookup countries for, we may have several
            if ( $conf{ip} ) {
                $conf{ip} = [ $conf{ip} ] unless ref $conf{ip};
                foreach my $ip ( @{ $conf{ip} } ) {
                    my $country = $self->get_country( $ip );
                    next unless $country;
                    if ( $country_meta{$country} ) {
                        push( @{ $country_meta{$country}->{ip} }, $ip );
                    }
                    else {
                        push( @country_list, $country );
                        $country_meta{$country} = {
                            ip => [$ip],
                        };
                    }
                }#foreach
            }#if
            # Are there extra countries to add to the start or end of the list
            if ( ref $conf{country_extra} ) {
                foreach my $position ( qw( end start ) ) {
                    if ( $conf{country_extra}->{$position} ) {
                        $conf{country_extra}->{$position} = [ $conf{country_extra}->{$position} ] unless ref $conf{country_extra}->{$position};
                        $conf{country_extra}->{$position} = [ map { lc $_ } @{ $conf{country_extra}->{$position} } ];
                        foreach my $country ( @{ $conf{country_extra}->{$position} } ) {
                            # Check if it's already in the list, in which case remove
                            if ( $country_meta{$country} ) {
                                $country_meta{$country}->{extra} ||= [];
                                push( @{ $country_meta{$country}->{extra} },  $position );
                                # If adding to the end, leave in current position, only move to start
                                @country_list = grep { $_ ne $country } @country_list if $position eq 'start';
                            }
                            else {
                                $country_meta{$country} = {
                                    extra => [ $position ],
                                };
                            }
                        }
                    }#if
                }#foreach
                # Add to front/back of list
                unshift( @country_list, @{ $conf{country_extra}->{start} } ) if ref $conf{country_extra}->{start};
                push( @country_list, @{ $conf{country_extra}->{end} } ) if ref $conf{country_extra}->{end};
            }#if
        }#else
        # Get lang tags from countries
        my @lang_country;
        my %country_seen;
        foreach my $country ( @country_list ) {
            $country_meta{$country}->{name} = $self->get_country_name( $country );
            my @lang_list = $self->get_country_lang( $country );
            foreach my $lang ( @lang_list ) {
                next if $country_seen{$lang};
                push( @lang_country, $lang );
                $country_seen{$lang}++;
            }
        }#foreach

        # Now lang list from accept_langs
        my @lang_accept;
        my %accept_seen;
        if ( $conf{accept_lang} ) {
            $conf{accept_lang} = [ $conf{accept_lang} ] unless ref $conf{accept_lang};
            foreach my $accept_lang ( @{ $conf{accept_lang} } ) {
                my @lang_list = $self->get_accept_lang( $accept_lang );
                foreach my $lang ( @lang_list ) {
                    next if $accept_seen{$lang};
                    push( @lang_accept, $lang );
                    $accept_seen{$lang}++;
                }
            }
        }
        # Are there extra lang tags to add to the start or end of the list
        my %extra_seen;
        my %extra_list;
        if ( ref $conf{lang_extra} ) {
            foreach my $position ( qw( end start ) ) {
                $extra_list{$position} = [];
                if ( $conf{lang_extra}->{$position} ) {
                    $conf{lang_extra}->{$position} = [ $conf{lang_extra}->{$position} ] unless ref $conf{lang_extra}->{$position};
                    $conf{lang_extra}->{$position} = [ map { lc $_ } @{ $conf{lang_extra}->{$position} } ];
                    $extra_list{$position} = $conf{lang_extra}->{$position};
                    $extra_seen{$position} = { map { $_ => 1 } @{ $conf{lang_extra}->{$position} } };
                }
            }#foreach
        }#if
        ## Rank languages based on order and appearance in both lists
        # Which lists they appear in
        foreach my $lang ( @lang_accept, @lang_country, @{ $extra_list{start} }, @{ $extra_list{end} } ) {
            next if $lang_meta{$lang};
            $lang_meta{$lang} = {
                both    => $accept_seen{$lang} && $country_seen{$lang} ? 1 : 0,
                accept  => $accept_seen{$lang} || 0,
                country => $country_seen{$lang} || 0,
                start   => $extra_seen{start}->{$lang} || 0,
                end     => $extra_seen{end}->{$lang} || 0,
                name    => $self->get_lang_name($lang),
            };
        }#foreach
        ## Rank position
        # Extra start will go first
        my $pos = 1;
        foreach my $lang ( @{ $extra_list{start} } ) {
            next if $lang_meta{$lang}->{pos};
            $lang_meta{$lang}->{pos} = $pos;
            $pos++;
        }#foreach
        # Then sequence
        my %lang_hash = (
            A => \@lang_accept,
            C => \@lang_country,
        );
        $rank{lang}->{start} ||= $rank{lang}->{repeat};
        my @sequence = split( //, $rank{lang}->{start} );
        while ( my $type = shift @sequence ) {
            last unless @{ $lang_hash{A} } || @{ $lang_hash{C} };
            push( @sequence, split( //, $rank{lang}->{repeat} ) ) unless @sequence;
            while ( my $lang = shift @{ $lang_hash{$type} } ) {
                if ( $lang_meta{$lang}->{pos} ) {
                    next;
                }
                else {
                    $lang_meta{$lang}->{pos} = $pos;
                    $pos++;
                    last;
                }
            }#while
        }#while
        # Extra end added to the end
        foreach my $lang ( @{ $extra_list{end} } ) {
            next if $lang_meta{$lang}->{pos};
            $lang_meta{$lang}->{pos} = $pos;
            $pos++;
        }#foreach
        # Prefer languages that appear in both?
        if ( $rank{lang_both} ) {
            $conf{lang} = [ sort {
                $lang_meta{$b}->{start} <=> $lang_meta{$a}->{start} ||
                $lang_meta{$b}->{both} <=> $lang_meta{$a}->{both} ||
                $lang_meta{$a}->{pos} <=> $lang_meta{$b}->{pos}
                } keys %lang_meta ];
        }
        else {
            $conf{lang} = [ sort {
                $lang_meta{$a}->{pos} <=> $lang_meta{$b}->{pos}
                } keys %lang_meta ];
        }
    }#else

    # Get the related charsets and meta data
    my @words = $self->get_words( $conf{text}, $conf{words} );
    my %char_hash = (
        W => [],
        M => [],
        L => [],
    );
    my %char_meta;
    my %char_error;
    foreach my $lang ( @{ $conf{lang} } ) {
        my @charsets = $self->get_lang_charset( $lang );
        next unless @charsets;
        my @os_list = ( 'W', 'M', 'L' );
        pop @os_list unless $conf{inc_linux};
        for ( my $i=0; $i <= $#os_list; $i++ ) {
            next if $char_error{ $charsets[$i] };
            if ( $char_meta{ $charsets[$i] } ) {
                push( @{ $char_meta{$charsets[$i]}->{lang} }, $lang );
            }
            else {
                # Test charset parses
                my $charset_encode = _try_charset( $charsets[$i], $conf{text} );
                if ( $charset_encode ) {
                    push( @{ $char_hash{ $os_list[$i] } }, $charsets[$i] );
                    $char_meta{ $charsets[$i] } = {
                        lang => [ $lang ],
                        words => [ map { decode( $charset_encode, $_ ) } @words ],
                    };
                }
                else {
                    $char_error{ $charsets[$i] }++;
                }
            }#else
        }#for
    }#foreach

    # Does this parse as UTF-8?
    my $is_utf8 = 1;
    eval { decode( 'UTF-8', $conf{text}, Encode::FB_CROAK ) };
    $is_utf8 = 0 if $@;
    # Make sure we have UTF-8 charset info
    if ( $is_utf8 ) {
        # UTF-8 could be any language, so doesn't tend to be picked up above
        $char_meta{'utf-8'} = {
            pos  => 1,
            lang => [],
            words => [ map { decode( 'UTF-8', $_ ) } @words ],
        };
    }
    else {
        $char_error{'utf-8'}++;
    }

    # Rank position
    $rank{char}->{ $conf{os} }->{start} ||= $rank{char}->{ $conf{os} }->{repeat};
    my @sequence = split( //, $rank{char}->{ $conf{os} }->{start} );
    my $pos = $is_utf8 ? 2 : 1;
    while ( my $type = shift @sequence ) {
        last unless @{ $char_hash{W} } || @{ $char_hash{M} } || @{ $char_hash{L} };
        push( @sequence, split( //, $rank{char}->{ $conf{os} }->{repeat} ) ) unless @sequence;
        while ( my $charset = shift @{ $char_hash{$type} } ) {
            if ( $char_meta{$charset}->{pos} ) {
                next;
            }
            else {
                $char_meta{$charset}->{pos} = $pos;
                $pos++;
                last;
            }
        }#while
    }#while

    # Can we see what Mozilla detection thinks?
    my $mozilla;
    if ( $has_detect ) {
        $mozilla = lc Encode::Detect::Detector::detect( $conf{text} );
        if ( $mozilla ) {
            # Check charset can decode
            my $charset_encode = _try_charset( $mozilla, $conf{text} );
            if ( $charset_encode ) {
                # Check we have the Mozilla charset in our list
                if ( $char_meta{$mozilla} ) {
                    $char_meta{$mozilla}->{mozilla} = 1;
                    # Should Mozilla affect position?
                    if ( $rank{mozilla_move} && $char_meta{$mozilla}->{pos} != 1 ) {
                        my $pos_new = $char_meta{$mozilla}->{pos} - $rank{mozilla_move};
                        $pos_new = 1 if $pos_new < 1;
                        # Move other charsets
                        map { $_->{pos}++ } grep {
                            $_->{pos} >= $pos_new &&
                            $_->{pos} < $char_meta{$mozilla}->{pos}
                        } values %char_meta;
                        $char_meta{$mozilla}->{pos} = $pos_new;
                    }
                }#if
                else {
                    # Insert Mozilla if it's not in list?
                    if ( $rank{mozilla_insert} ) {
                        # Push everything else down
                        map { $_->{pos}++ } grep {
                            $_->{pos} >= $rank{mozilla_insert}
                        } values %char_meta;
                        $char_meta{$mozilla} = {
                            lang    => [],
                            words   => [ map { decode( $charset_encode, $_ ) } @words ],
                            pos     => $rank{mozilla_insert},
                            mozilla => 1,
                        };
                    }
                }#else
            }#if
            else {
                $char_error{ $mozilla }++;
            }
        }#if
    }#if

    # Prep return
    my @charsets = sort { $char_meta{$a}->{pos} <=> $char_meta{$b}->{pos} } keys %char_meta;
    if ( wantarray ) {
        my %meta = (
            charsets => \%char_meta,
            lang     => \%lang_meta,
            country  => \%country_meta,
            error    => [ keys %char_error ],
        );
        return ( \@charsets, \%meta);
    }
    else {
        return $charsets[0];
    }
}#sub


sub _try_charset {
    my ( $charset, $text ) = @_;
    # Older versions of Encode::Alias don't map x-mac-* encodings properly
    $charset =~ s/^(?:x[_-])?mac[_-](.*)$/mac$1/;
    $charset =~ s/^macce$/maccentraleurroman/;
    eval { decode( $charset, $text, Encode::FB_CROAK ) };
    return $@ ? 0 : $charset;
}#sub


=back

=head1 RANKING SYSTEM

Unfortunately the heuristics employed by this method aren't straight forward. Several key scenarios are taken into consideration, namely:

The upload charset is:
for the language that matches the browsers language settings and OS.
for the language that matches the uploaders countries official language and OS.
for the language that matches the browsers language settings, but a different OS.
for the language that matches the uploaders countries official language, but a different OS.
unrelated, hopefully detected by Mozilla's universal charset detector.

Although the browsers language setting is preferred, it's not unusually for it
to be incorrect. For example a surprising number of UK users have en-US rather
than en-GB. In such instances the language from the IP would be more accurate.
For this reason if the Mozilla detected charset matches an IP dervied charset it
is brought to the front.
However, an Englishman uploading a file whilst abroad would not give an accurate
language from IP. Likewise, some countries like South Africa have several
recognised languages.
Some countries have inhabitants that use either Latin or Cyrillic alphabets for
the same language. In these instances, the Mozilla detector is used to determine
which is more likely, but both options will be returned.
The use of Macintosh computers has been on the rise, as has the appearance of
their charsets. In fact that's what led me to write this module, as the Mozilla
detector doesn't cover every encoding and was missing Mac-Roman. Generally
Windows users are less likely to upload files with Macintosh encoding, Although
the same cannot be said the other way around. For this reason, when the OS is
Macintosh it's matching charsets will come first, followed by the likely
Windows, alternating between the two.

We assume linux systems are mostly UTF-8 these days, that their pre-UTF-8 ISO
charsets were roughly the same as the Windows equivalents, and that Linux users
are generally more computer savvy. For these reasons Linux charsets are not
included in results by default.

Rather than ranking charsets through some kind of weighting based on appearance,
we apply configurable patterns. Weight would always favour common charsets,
hopefully the ranking patterns work better.

This is the first version of this module. I'm open to suggestions with regards
improved heuristics, and possibly configurable heuristics.

You can override the default ranking by passing the appropriate data structure
to detect(). You need to at least provide the repeat string for lang and all the
OSs.

IP country lookup and accept_language parsing is used initially to generate a
list of matching languages. The order in which these are then ranked is based
on their appearance (accept_lang), or popularity (country), and the sequence
given. A represents accept_lang and C represents country, so a sequence starting
with AC and repeating with AC would generate ACACACACAC... until there are no
matching languages left. The lang_both option pushes charsets that come from
both accept_lang and country.

Next charsets are matched from the languages by OS. Depending on what OS has
been passed, or detected from user_agent. The char sequences contain W for
Windows, M for Macintosh or L for Linux. The Linux charsets are filtered out
unless the OS is Linux or the inc_linux config option is enabled. So a Windows
OS with sequence starting WW and repeating WML would generate WWWMWMWMWM...
matching the first 3 likely windows charsets, then the most likely Macintosh,
etc. Charsets are tested to see if they can decode the text, invalid ones are
filtered out.

The string is tested to see whether it looks like UTF-8. If it does that's
pushed to the front on the list. If the Mozilla charset detector is available
it's used to see what charset it returns. The option mozilla_move sets how the
many places to move the matching charset forward in the list. The
mozilla_insert options defines in what position to insert the Mozilla match if
it's not already in the list.

    my %ranking = (
        lang => {
            start  => 'AC',
            repeat => 'AC',
        },
        # Rank languages that appear in both country and accept_lang first
        lang_both => 1,
        char => {
            windows => {
                start  => 'WW',
                repeat => 'WML',
            },
            macintosh => {
                start  => 'M',
                repeat => 'MWL',
            },
            linux => {
                start  => 'LWM',
                repeat => 'LWM',
            },
        },
        # Mozilla detected charset options
        mozilla_move => 1, # Number of positions to move the forward
        mozilla_insert => 3, # At what position to insert if it's not in list
    );
    my $charset = $detector->detect( ranking => \%ranking );

=head1 LICENSE

This is released under the Artistic
License. See L<perlartistic>.

=head1 AUTHOR

Lyle Hopkins - L<http://www.cosmicperl.com/>

Development kindly sponsored by - L<http://www.greenrope.com/>

=head1 REFERENCES

I had a hard time finding good data sources, all the information I needed was
pretty spread out. These are the main sites I used, but there was lots of
googling to fill in the gaps.

L<http://www.science.co.il/language/locale-codes.asp>
L<http://www.mydigitallife.info/ansi-code-page-for-windows-system-locale-with-identifier-constants-and-strings/>
L<http://webcheatsheet.com/html/character_sets_list.php>
L<http://www.w3.org/International/O-charset-lang.html>
L<http://www.eki.ee/itstandard/docs/draft-alvestrand-lang-char-03.txt>
L<http://tlt.its.psu.edu/suggestions/international/bylanguage/index.html>
L<http://docs.oracle.com/javase/1.5.0/docs/guide/intl/locale.doc.html>
L<http://www-archive.mozilla.org/projects/intl/chardet.html>
L<http://download.geonames.org/export/dump/countryInfo.txt>

=head1 SEE ALSO

L<Encode::Detect::Detector>, L<Encode>, L<Geo::IP>, L<IP::Country>

=head1 TODO

Make default between Latin and Cyrillic based on popularity in language
Write some tests
Rank regions differently?

=cut


sub any {
    my ( $var, $list ) = @_;
    foreach (@$list) {
        return 1 if $var eq $_;
    }#foreach
    return 0;
}#sub


1;
