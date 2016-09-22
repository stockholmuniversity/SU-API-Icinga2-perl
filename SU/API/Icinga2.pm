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
    my $self = {
        hostname => shift,
        port => shift,
        path => shift,
        version => shift,
        insecure => shift,
    };

    if ($self->{path} !~ /\/$/) {
        $self->{path} .= "/";
    }
    $self->{url} = "https://$self->{hostname}:$self->{port}$self->{path}v$self->{version}";

    if ($self->{insecure}) {
        $self->{ua} = LWP::UserAgent->new( ssl_opts => {verify_hostname => 0 } );
    } else {
        $self->{ua} = LWP::UserAgent->new;
    };

    $self->{ua}->default_header('Accept' => 'application/json');
    $self->{login_status} = "not logged in";

    bless $self, $class;
    return $self;
};

sub do_request {
    my ($self,$method,$uri,$params,$data) = @_;

    my $request_url;
    $request_url = "$self->{url}/${uri}";

    if ($params) {
        $params = encode_params($params);
        $request_url = "$self->{url}/${uri}?$params";
    };
    my $req = HTTP::Request->new($method => $request_url);

    if ($data) {
        $data = encode_json($data);
        $req->content($data);
     };

    $self->{res} = $self->{ua}->request($req);

    if (!$self->{res}->is_success) {
        return undef;
    };
    # Handle non utf8 chars
    my $json_result = decode_json(encode_utf8($self->{res}->content));

    if ($json_result) {
        return $json_result;
    };
    return undef;
};

sub encode_params {
    my $filter = $_[0];
    my @filter_array;
    my @encoded_uri_array;

    if($filter =~ /&/) {
        @filter_array = split('&',$filter);
    } else {
        @filter_array = $filter;
    };
    for(@filter_array) {
        if($_ =~ /=/) {
            my ($argument,$value) = split("=",$_);
            push(@encoded_uri_array,join("=",uri_escape($argument),uri_escape($value)));
        } else {
            push(@encoded_uri_array,uri_escape($_));
        };
    };
    return join("&",@encoded_uri_array);
};

sub login {
    my ($self,$username,$password) = @_;

    $self->{username} = $username;
    $self->{password} = $password;

    $self->{ua}->credentials("$self->{hostname}:$self->{port}", "Icinga 2", $self->{username}, $self->{password});

    $self->do_request("GET", "/status", "", "");


    if ($self->request_code == 200 ) {
        $self->{login_status} = "login successful";
        $self->{logged_in} = 1;
    } elsif ($self->request_code == 401) {
        $self->{login_status} = "wrong username/password";
    } else {
        $self->{login_status} = "unknown status line: " . $self->{res}->status_line;
    }

    return $self->{logged_in};
};

sub logout {
    my ($self) = @_;
    $self->{logged_in} = undef;
};

sub request_code {
    my ($self) = @_;
    return $self->{res}->code;
};

sub request_status_line {
    my ($self) = @_;
    return $self->{res}->status_line;
};

sub logged_in {
    my ($self) = @_;
    return $self->{logged_in};
};

sub login_status {
    my ($self) = @_;
    return $self->{login_status};
};

sub DESTROY {
    my ($self) = @_;
    if ($self->{ua} && $self->{logged_in}) {
        $self->logout();
    } elsif ($self->{logged_in}) {
        warn "Automatic logout failed";
    };
};

1;
