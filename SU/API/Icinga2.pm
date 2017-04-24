package SU::API::Icinga2;

use strict;
use warnings;

use LWP::UserAgent;
use HTTP::Request;
use URI::Escape;
use JSON;
use Encode qw( encode_utf8 );

sub new {
    my $class = shift;
    my $self  = {
        hostname => shift,
        port     => shift,
        path     => shift,
        version  => shift,
        insecure => shift,
    };

    if ( $self->{path} !~ /\/$/ ) {
        $self->{path} .= "/";
    }
    $self->{url} =
      "https://$self->{hostname}:$self->{port}$self->{path}v$self->{version}";

    if ( $self->{insecure} ) {
        $self->{ua} =
          LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
    }
    else {
        $self->{ua} = LWP::UserAgent->new;
    }

    $self->{ua}->default_header( 'Accept' => 'application/json' );
    $self->{login_status} = "not logged in";

    bless $self, $class;
    return $self;
}

sub do_request {
    my ( $self, $method, $uri, $params, $data, $plaintext ) = @_;

    my $request_url;
    $request_url = "$self->{url}/${uri}";

    if ($params) {
        $params      = encode_params($params);
        $request_url = "$self->{url}/${uri}?$params";
    }
    my $req = HTTP::Request->new( $method => $request_url );

    if ($data) {
        $data = encode_json($data);
        $req->content($data);
    }

    $self->{res} = $self->{ua}->request($req);

    if ( !$self->{res}->is_success ) {
        return undef;
    }

    # Try with first plaintext if plaintext is set
    if ($plaintext) {
        my $str = encode_utf8( $self->{res}->content );
        if ($str) {
            return $str;
        }
    }

    # Handle non utf8 chars
    my $json_result = decode_json( encode_utf8( $self->{res}->content ) );
    if ($json_result) {
        return $json_result;
    }
    return undef;
}

sub encode_params {
    my $filter = $_[0];
    my @filter_array;
    my @encoded_uri_array;

    if ( $filter =~ /&/ ) {
        @filter_array = split( '&', $filter );
    }
    else {
        @filter_array = $filter;
    }
    for (@filter_array) {
        if ( $_ =~ /=/ ) {
            my ( $argument, $value ) = split( "=", $_ );
            push( @encoded_uri_array,
                join( "=", uri_escape($argument), uri_escape($value) ) );
        }
        else {
            push( @encoded_uri_array, uri_escape($_) );
        }
    }
    return join( "&", @encoded_uri_array );
}

sub export {

    my ( $self, $full, $api_only ) = @_;
    my $result        = decode_json( encode_utf8( $self->{res}->content ) );
    my $type          = $result->{results}[0]{type};
    my @allowed_types = (
        "CheckCommand", "Host",       "HostGroup", "Service",
        "ServiceGroup", "TimePeriod", "User",      "UserGroup"
    );

    # We only support certain object types
    unless ( grep( /$type/, @allowed_types ) ) {
        return undef;
    }

    my @keys;

    if ( $type eq "CheckCommand" ) {
        @keys = ( "arguments", "command", "env", "vars", "timeout" );
        if ($full) {
            push @keys, ( "templates", "zone" );
        }
    }
    elsif ( $type eq "Host" ) {
        @keys = (
            "address6",       "address",
            "check_command",  "display_name",
            "event_command",  "action_url",
            "notes",          "notes_url",
            "vars",           "icon_image",
            "icon_image_alt", "check_interval",
            "max_check_attempts", "retry_interval"
        );
        if ($full) {
            push @keys,
              (
                "check_period",          "check_timeout",
                "enable_active_checks",  "enable_event_handler",
                "enable_flapping",       "enable_notifications",
                "enable_passive_checks", "enable_perfdata",
                "groups",                "notes",
                "retry_interval",        "templates",
                "zone"
              );
        }
    }
    elsif ( $type eq "HostGroup" ) {
        @keys = ( "action_url", "display_name", "notes", "notes_url", "vars" );
        if ($full) {
            push @keys, ( "groups", "templates", "zone" );
        }
    }
    elsif ( $type eq "Service" ) {
        @keys = (
            "vars",               "action_url",
            "check_command",      "check_interval",
            "display_name",       "notes",
            "notes_url",          "event_command",
            "max_check_attempts", "retry_interval"
        );
        if ($full) {
            push @keys,
              (
                "check_period",          "check_timeout",
                "enable_active_checks",  "enable_event_handler",
                "enable_flapping",       "enable_notifications",
                "enable_passive_checks", "enable_perfdata",
                "groups",                "icon_image",
                "icon_image_alt",        "notes",
                "templates",             "zone"
              );
        }
    }
    elsif ( $type eq "ServiceGroup" ) {
        @keys = ( "action_url", "display_name", "notes", "notes_url", "vars" );
        if ($full) {
            push @keys, ( "groups", "templates", "zone" );
        }
    }
    elsif ( $type eq "TimePeriod" ) {
        @keys = (
            "display_name", "excludes",
            "includes",     "prefer_includes",
            "ranges",       "vars"
        );
        if ($full) {
            push @keys, ( "templates", "zone" );
        }
    }
    elsif ( $type eq "User" ) {
        @keys = (
            "display_name",         "email",
            "enable_notifications", "pager",
            "states",               "period",
            "vars"
        );
        if ($full) {
            push @keys, ( "groups", "templates", "zone" );
        }
    }
    elsif ( $type eq "UserGroup" ) {
        @keys = ( "display_name", "vars" );
        if ($full) {
            push @keys, ( "groups", "templates", "zone" );
        }
    }
    my @results;
    foreach my $object ( @{ $result->{results} } ) {
        # The object needs to know its own name stored in a read/write field
        $object->{attrs}{vars}{__export_name} = $object->{attrs}{__name};
        
        my %hash;
        foreach my $key (sort @keys) {
            $hash{attrs}{$key} = $object->{attrs}{$key};
        }
        if ($api_only) {
            if ($object->{attrs}{package} eq "_api") {
                push @results, \%hash;
            }
        }
        else {
            push @results, \%hash;
        }

    }
    return \@results;

}

sub login {
    my ( $self, $username, $password ) = @_;

    $self->{username} = $username;
    $self->{password} = $password;

    $self->{ua}->credentials( "$self->{hostname}:$self->{port}",
        "Icinga 2", $self->{username}, $self->{password} );

    $self->do_request( "GET", "/status", "", "" );

    if ( $self->request_code == 200 ) {
        $self->{login_status} = "login successful";
        $self->{logged_in}    = 1;
    }
    elsif ( $self->request_code == 401 ) {
        $self->{login_status} = "wrong username/password";
    }
    else {
        $self->{login_status} =
          "unknown status line: " . $self->{res}->status_line;
    }

    return $self->{logged_in};
}

sub logout {
    my ($self) = @_;
    $self->{logged_in} = undef;
}

sub request_code {
    my ($self) = @_;
    return $self->{res}->code;
}

sub request_status_line {
    my ($self) = @_;
    return $self->{res}->status_line;
}

sub logged_in {
    my ($self) = @_;
    return $self->{logged_in};
}

sub login_status {
    my ($self) = @_;
    return $self->{login_status};
}

sub DESTROY {
    my ($self) = @_;
    if ( $self->{ua} && $self->{logged_in} ) {
        $self->logout();
    }
    elsif ( $self->{logged_in} ) {
        warn "Automatic logout failed";
    }
}

1;
