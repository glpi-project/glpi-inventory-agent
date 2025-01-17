package GLPI::Agent::HTTP::Client;

use strict;
use warnings;

use English qw(-no_match_vars);
use URI;
use HTTP::Request;
use HTTP::Status;
use LWP::UserAgent;
use UNIVERSAL::require;
use Digest::SHA qw(sha256_hex);
use Cpanel::JSON::XS;

use GLPI::Agent;
use GLPI::Agent::Logger;
use GLPI::Agent::Tools;
use GLPI::Agent::Tools::Expiration;
use GLPI::Agent::Protocol::Message;

use constant    _log_prefix => "[http client] ";

# Keep SSL_ca for storing read local certificate store at the class level
my $_SSL_ca;

# Keep Oauth2 access token
my $oauth2;

sub new {
    my ($class, %params) = @_;

    my $config = $params{config} // {};

    my $ca_cert_file = $params{ca_cert_file} || $config->{'ca-cert-file'};
    die "non-existing certificate file $ca_cert_file"
        if $ca_cert_file && ! -f $ca_cert_file;

    my $ca_cert_dir = $params{ca_cert_dir} || $config->{'ca-cert-dir'};
    die "non-existing certificate directory $ca_cert_dir"
        if $ca_cert_dir && ! -d $ca_cert_dir;

    my $ssl_cert_file = $params{ssl_cert_file} || $config->{'ssl-cert-file'};
    die "non-existing client certificate file $ssl_cert_file"
        if $ssl_cert_file && ! -f $ssl_cert_file;

    # We should still keep SSL certs cache if running in long running netdiscovery
    # or netinventory task with expiration set in a dedicated thread
    $_SSL_ca->{_expiration} = getExpirationTime()
        if $_SSL_ca && $_SSL_ca->{_expiration} && getExpirationTime();

    my $self = {
        logger          => $params{logger} || GLPI::Agent::Logger->new(),
        user            => $params{user}     || $config->{'user'},
        password        => $params{password} || $config->{'password'},
        oauth_client    => $params{oauth_client} || $config->{'oauth-client-id'},
        oauth_secret    => $params{oauth_secret} || $config->{'oauth-client-secret'},
        ssl_set         => 0,
        no_ssl_check    => $params{no_ssl_check} || $config->{'no-ssl-check'},
        no_compress     => $params{no_compress}  || $config->{'no-compression'},
        ca_cert_dir     => $ca_cert_dir,
        ca_cert_file    => $ca_cert_file,
        ssl_cert_file   => $ssl_cert_file,
        ssl_fingerprint => $params{ssl_fingerprint} || $config->{'ssl-fingerprint'},
        ssl_keystore    => $params{ssl_keystore} || $config->{'ssl-keystore'},
        _vardir         => $config->{'vardir'},
    };
    bless $self, $class;

    # create user agent
    $self->{ua} = LWP::UserAgent->new(
        requests_redirectable => ['POST', 'GET', 'HEAD'],
        agent                 => $GLPI::Agent::AGENT_STRING,
        timeout               => $params{timeout} || $config->{'timeout'} || 180,
        parse_head            => 0, # No need to parse HTML
        keep_alive            => 1,
    );

    my $proxy = $params{proxy} || $config->{'proxy'};
    if ($proxy) {
        $self->{ua}->proxy(['http', 'https'], $proxy);
    } else {
        $self->{ua}->env_proxy();
    }

    # check compression mode
    if (!$self->{no_compress} && Compress::Zlib->require()) {
        # RFC 1950
        $self->{compression} = 'zlib';
        $self->{logger}->debug2(_log_prefix . "Using Compress::Zlib for compression");
    } elsif (!$self->{no_compress} && canRun('gzip')) {
        # RFC 1952
        $self->{compression} = 'gzip';
        $self->{logger}->debug2(_log_prefix . "Using gzip for compression");
    } else {
        $self->{compression} = 'none';
        $self->{logger}->debug2(_log_prefix . "Not using compression");
    }

    # Set content-type header relative to selected compression
    $self->{ua}->default_header('Content-type' =>
        $self->{compression} eq 'zlib' ? "application/x-compress-zlib" :
        $self->{compression} eq 'gzip' ? "application/x-compress-gzip" :
                                         "application/json"
    );

    return $self;
}

sub timeout {
    my ($self, $timeout) = @_;

    # Get/set LWP::UserAgent timeout as required
    return $self->{ua}->timeout($timeout);
}

sub request {
    my ($self, $request, $file, $no_proxy_host, $timeout, %skiperror) = @_;

    my $logger = $self->{logger};

    # Save current timeout to restore it before leaving
    my $current_timeout = $self->{ua}->timeout();
    $self->{ua}->timeout($timeout)
        if defined($timeout);

    my $url = $request->uri();
    my $scheme = $url->scheme();
    $self->_setSSLOptions() if $scheme eq 'https' && !$self->{ssl_set};

    # Avoid to use proxy if requested
    if ($no_proxy_host) {
        $self->{ua}->no_proxy($no_proxy_host);
    } elsif ($self->{ua}->proxy($scheme)) {
        # keep proxy trace if one may be used
        my $proxy_uri = URI->new($self->{ua}->proxy($scheme));
        if ($proxy_uri->userinfo) {
            # Obfuscate proxy password if present
            my ($proxy_user, $proxy_pass) = split(':', $proxy_uri->userinfo);
            $proxy_uri->userinfo( $proxy_user.":".('X' x length($proxy_pass)) )
                if ($proxy_pass);
        }
        $logger->debug(
            _log_prefix .
            "Using '".$proxy_uri->as_string()."' as proxy for $scheme protocol"
        );
    }

    # Try to set Bearer header if oauth2 access token has still been requested
    if ($oauth2) {
        my $key = $url->as_string;
        if ($oauth2->{$key}) {
            # Update access token using current url clone if expired
            $self->_getOauthAccessToken($url->clone())
                if time >= $oauth2->{$key}->{expires};

            if ($oauth2->{$key}) {
                # Add token bearer as Authorization header
                $request->header(Authorization => "Bearer " . $oauth2->{$key}->{token});

                $logger->debug(
                    _log_prefix .
                    "submitting request with access token authorization"
                );
            } else {
                $logger->debug(
                    _log_prefix .
                    "no more oauth access token authorization available"
                );
            }
        }
    }

    my $result = HTTP::Response->new( 500 );
    eval {
        if ($OSNAME eq 'MSWin32' && $scheme eq 'https') {
            alarm $self->{ua}->timeout();
        }
        $result = $self->{ua}->request($request, $file);
        alarm 0;
    };

    # Debug SSL support status when no requesting security
    if ($self->{no_ssl_check}) {
        my $headers = $result->headers();
        my $warning = $headers->header("Client-SSL-Warning");
        $logger->info(_log_prefix . "SSL Client warning: $warning") if $warning;

        my $class = $headers->header("Client-SSL-Socket-Class");
        if ($class && $class eq "IO::Socket::SSL") {
            my $infos = "";
            foreach my $header (qw/Client-SSL-Cert-Issuer Client-SSL-Cert-Subject Client-SSL-Version Client-SSL-Cipher/) {
                my $string = $headers->header($header)
                    or next;
                $infos .= ", " if $infos;
                $header =~ /^Client-SSL-(.*)$/;
                $infos .= "$1: '$string'";
            }
            $logger->info(_log_prefix . "SSL Client info: $infos") if $infos;

            # fingerprint IO::Socket::SSL API is only available since IO::Socket::SSL v1.967
            if ($IO::Socket::SSL::VERSION >= 1.967) {
                my $fingerprint;
                my ($socket) = $self->{ua}->conn_cache->get_connections('https');
                $fingerprint = $socket->get_fingerprint() if $socket;
                if ($fingerprint) {
                    $logger->info(_log_prefix . "SSL server certificate fingerprint: $fingerprint");
                    $logger->info(_log_prefix . "You can set it in conf as 'ssl-fingerprint' and disable 'no-ssl-check' option to trust that server certificate");
                }
            }
        }
    }

    # check result first
    if (!$result->is_success()) {
        # authentication required
        if ($result->code() == 401) {
            if ($self->{oauth_client} && $self->{oauth_secret}) {
                # Get access token using current url clone
                $self->_getOauthAccessToken($url->clone());

                my $oauth_token = $oauth2->{$url->as_string};
                if ($oauth_token) {
                    # Add token bearer as Authorization header
                    $request->header(Authorization => "Bearer " . $oauth_token->{token});

                    $logger->debug(
                        _log_prefix .
                        "authentication required, submitting request with access token authorization"
                    );

                    # replay request
                    eval {
                        if ($OSNAME eq 'MSWin32' && $scheme eq 'https') {
                            alarm $self->{ua}->{timeout};
                        }
                        $result = $self->{ua}->request($request, $file);
                        alarm 0;
                    };
                    if (!$result->is_success()) {
                        my $error = $result->code() == 401 ?
                            "authentication required, wrong access token" :
                            "authentication required, error status: " . $result->status_line();
                        my $message = $result->content();
                        if (length($message)) {
                            my $contentType = $result->header('content-type');
                            $message = $self->uncompress($message, $contentType) if $contentType && $contentType =~ /x-compress/;
                            if ($message && $message =~ /^{/) {
                                my $content = GLPI::Agent::Protocol::Message->new(message => $message);
                                if ($content->status eq 'error' && $content->get('message')) {
                                    $error = $content->get('message');
                                }
                            }
                        }
                        $logger->error(_log_prefix . $error);
                    }
                }
            } elsif ($self->{user} && $self->{password}) {
                $logger->debug(
                    _log_prefix .
                    "authentication required, submitting credentials"
                );
                # compute authentication parameters
                my @headers = split(/\s*,\s*/, $result->header('www-authenticate'));
                # Parse headers for supported scheme
                my %authenticate;
                foreach my $header (@headers) {
                    if ($header =~ /^Basic realm="(.*)"/) {
                        $authenticate{basic} = $1;
                    }
                }
                my @authen;
                push @authen, 'basic' if $authenticate{basic};
                my $host = $url->host();
                my $port = $url->port() ||
                   ($scheme eq 'https' ? 443 : 80);
                foreach my $authen (@authen) {
                    $logger->debug(
                        _log_prefix .
                        "authentication required, trying $authen with $self->{user} user" .
                        ( $authenticate{$authen} ? " ($authenticate{$authen})" : "" )
                    );
                    $self->{ua}->credentials(
                        "$host:$port",
                        $authenticate{$authen},
                        $self->{user},
                        $self->{password},
                    );
                    # replay request
                    eval {
                        if ($OSNAME eq 'MSWin32' && $scheme eq 'https') {
                            alarm $self->{ua}->{timeout};
                        }
                        $result = $self->{ua}->request($request, $file);
                        alarm 0;
                    };
                    last if $result->is_success();
                    $logger->debug(_log_prefix."$authen authentication failed");
                }
                if (!$result->is_success()) {
                    $logger->error(
                        _log_prefix .
                        ($result->code() == 401 ?
                            "authentication required, wrong credentials" :
                            "authentication required, error status: " . $result->status_line())
                    );
                }
            } else {
                my $error = "authentication required, no credentials available";

                # Try to extract error message if given
                if ($result->header('content-length')) {
                    my $contentType = $result->header('content-type');
                    my $message = $result->content();
                    $message = $self->uncompress($message, $contentType) if $contentType && $contentType =~ /x-compress/;
                    if ($message && $message =~ /^{/) {
                        my $content = GLPI::Agent::Protocol::Message->new(message => $message);
                        if ($content->status eq 'error' && $content->get('message')) {
                            $error = $content->get('message');
                        }
                    } elsif ($message && $message =~ /^</) {
                        if (GLPI::Agent::XML->require()) {
                            my $xml = GLPI::Agent::XML->new(string => $message);
                            my $tree = $xml->dump_as_hash();
                            ($error) = grep { $_ } split("\n", $tree->{REPLY}->{ERROR})
                                if $tree && ref($tree->{REPLY}) eq 'HASH' && exists($tree->{REPLY}->{ERROR});
                        }
                    }
                }

                # abort
                $logger->error(_log_prefix . $error);
            }

        } elsif ($result->code() == 407) {
            $logger->error(
                _log_prefix .
                "proxy authentication required, wrong or no proxy credentials"
            );

        } else {
            # check we request through a proxy
            my $proxyreq = defined $result->request->{proxy};

            my @message = ($result->status_line());
            my $contentType = $result->header('content-type');
            my $message = $result->content();
            $message = $self->uncompress($message, $contentType) if $contentType && $contentType =~ /x-compress/;
            if ($message && $message =~ /^{/) {
                if (GLPI::Agent::Protocol::Message->require()) {
                    my $content = GLPI::Agent::Protocol::Message->new(message => $message);
                    if ($content->status eq 'error' && $content->get('message')) {
                        push @message, $content->get('message');
                    }
                }
            } elsif ($message && $message =~ /^</) {
                if (GLPI::Agent::XML->require()) {
                    my $xml = GLPI::Agent::XML->new(string => $message);
                    my $tree = $xml->dump_as_hash();
                    push @message, grep { $_ } split("\n", $tree->{REPLY}->{ERROR})
                        if $tree && ref($tree->{REPLY}) eq 'HASH' && exists($tree->{REPLY}->{ERROR});
                }
            }

            # Add info if the error comes from the client itself
            my $error_type = ($proxyreq ? "proxy" : "communication")." error";
            my $warning = $result->header('client-warning') // '';
            $error_type = lc($warning) if $warning;

            # Eventually add detailed SSL error message
            if ($self->{ssl_set} && $IO::Socket::SSL::SSL_ERROR) {
                my $strcheck = IO::Socket::SSL::SSL_WANT_READ()."|".IO::Socket::SSL::SSL_WANT_WRITE();
                push @message, $IO::Socket::SSL::SSL_ERROR
                    unless $IO::Socket::SSL::SSL_ERROR =~ /$strcheck/;
            }

            $logger->error(
                _log_prefix . $error_type . ": " . join(", ", @message)
            ) unless $skiperror{$result->code()};
        }
    }

    # Always restore timeout
    $self->{ua}->timeout($current_timeout);

    return $result;
}

sub _getOauthAccessToken {
    my ($self, $url) = @_;

    if (empty($self->{oauth_client}) || empty($self->{oauth_secret})) {
        $self->{logger}->error(
            _log_prefix .
            "oauth access token missing"
        );
        return;
    }

    my $key = $url->as_string;
    # Cleanup eventually still stored token
    delete $oauth2->{$key};

    # Guess access token api path from url
    my $path = $url->path();
    $path = $1 if $path =~ /^(.*)(marketplace|plugins).*$/;
    $path =~ s{/+$}{};
    $path .= '/' unless empty($path);
    $path .= 'api.php/token';
    $url->path($path);

    $self->{logger}->debug(
        _log_prefix .
        "authentication required, querying oauth access token on ".$url->as_string
    );

    my $request = HTTP::Request->new(POST => $url);
    my $json = GLPI::Agent::Protocol::Message->new(
        message => {
            grant_type      => "client_credentials",
            client_id       => $self->{oauth_client},
            client_secret   => $self->{oauth_secret},
            scope           => "inventory",
        }
    );
    my $content = $json->getRawContent();
    $request->header('Content-Type' => 'application/json');
    $request->header('Content-Length' => length($content));
    $request->content($content);

    # Don't log secrets
    my $sha256 = sha256_hex($content);
    $content =~ s/client_id":"[^"]*"/client_id":"CLIENT_ID"/;
    $content =~ s/client_secret":"[^"]*"/client_secret":"CLIENT_SECRET"/;
    $self->{logger}->debug2(_log_prefix . "sending message: (real content sha256sum: $sha256)\n$content");

    # play token request
    my $result;
    eval {
        if ($OSNAME eq 'MSWin32' && $url->scheme() eq 'https') {
            alarm $self->{ua}->{timeout};
        }
        $result = $self->{ua}->request($request);
        alarm 0;
    };

    unless ($result) {
        $self->{logger}->error(_log_prefix . "Failed to request oauth access token: no response");
        return;
    }

    my $message = $result->content();
    my $contentType = $result->header('content-type');
    $self->{logger}->debug2(_log_prefix . "received message: ($contentType)\n$message")
        if length($message) && $contentType;

    if ($result->is_success()) {
        if (length($message) && $contentType =~ m{application/json}i) {
            my $content = GLPI::Agent::Protocol::Message->new(message => $message);
            my $token = $content->converted();
            if ($token->{token_type} && $token->{token_type} eq 'Bearer' && !empty($token->{access_token})) {
                $oauth2->{$key} = {
                    token   => $token->{access_token},
                    expires => time + ($token->{expires_in} && $token->{expires_in} =~ /^\d+$/ ? $token->{expires_in} : 60),
                };
                $self->{logger}->debug(_log_prefix . "Bearer oauth token received (expiration: $token->{expires_in}s)\n");
            } else {
                $self->{logger}->error(_log_prefix . "Unsupported token returned from oauth server");
            }
        } else {
            $self->{logger}->error(_log_prefix . "Unsupported response returned from oauth server");
        }
    } else {
        $self->{logger}->error(_log_prefix . "Failed to request oauth access token: ".$result->status_line());
    }
}

sub _setSSLOptions {
    my ($self) = @_;

    # SSL handling
    if ($self->{no_ssl_check}) {
       # LWP 6 default behaviour is to check hostname
       # Fedora also backported this behaviour change in its LWP5 package, so
       # just checking on LWP version is not enough
       $self->{ua}->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0)
           if $self->{ua}->can('ssl_opts');
    } else {
        # only IO::Socket::SSL can perform full server certificate validation,
        # Net::SSL is only able to check certification authority, and not
        # certificate hostname
        IO::Socket::SSL->require();
        die
            "IO::Socket::SSL Perl module not available, "              .
            "unable to validate SSL certificates "                     .
            "(workaround: use 'no-ssl-check' configuration parameter)"
            if $EVAL_ERROR;

        # Activate SSL Debug if Stderr is in backends
        my $DEBUG_SSL = 0;
        $DEBUG_SSL = grep { ref($_) =~/Stderr$/ } @{$self->{logger}{backends}}
            if (ref($self->{logger}{backends}) eq 'ARRAY');
        if ( $DEBUG_SSL && $self->{logger}->debug_level() >= 2 ) {
            $Net::SSLeay::trace = 3;
        }

        # Support keychain on Darwin and keystore on MSWin32
        my $SSL_ca = $self->_KeyChain_or_KeyStore_Export();

        if ($LWP::VERSION >= 6) {
            $self->{ua}->ssl_opts(SSL_ca_file => $self->{ca_cert_file})
                if $self->{ca_cert_file};
            $self->{ua}->ssl_opts(SSL_ca_path => $self->{ca_cert_dir})
                if $self->{ca_cert_dir};
            $self->{ua}->ssl_opts(SSL_cert_file => $self->{ssl_cert_file})
                if $self->{ssl_cert_file};
            $self->{ua}->ssl_opts(SSL_fingerprint => $self->{ssl_fingerprint})
                if $self->{ssl_fingerprint} && $IO::Socket::SSL::VERSION >= 1.967;
            # Use SSL_ca option to support system keychain or keystore to add
            # discovered certificates to public ones
            $self->{ua}->ssl_opts(SSL_ca => $SSL_ca)
                if $SSL_ca && @{$SSL_ca};
        } else {
            # SSL_verifycn_scheme and SSL_verifycn_name are required
            die
                "IO::Socket::SSL Perl module too old "                     .
                "(available: $IO::Socket::SSL::VERSION, required: 1.14), " .
                "unable to validate SSL certificates "                     .
                "(workaround: use 'no-ssl-check' configuration parameter)"
                if $IO::Socket::SSL::VERSION < 1.14;

            # use a custom HTTPS handler to workaround default LWP5 behaviour
            GLPI::Agent::HTTP::Protocol::https->use(
                ca_cert_file => $self->{ca_cert_file},
                ca_cert_dir  => $self->{ca_cert_dir},
                ssl_cert_file => $self->{ssl_cert_file},
                ssl_fingerprint => $self->{ssl_fingerprint},
                ssl_ca => $SSL_ca,
            );

            LWP::Protocol::implementor(
                'https', 'GLPI::Agent::HTTP::Protocol::https'
            );

            # abuse user agent internal to pass values to the handler, so
            # as to have different behaviors in the same process
            $self->{ua}->{ssl_check} = $self->{no_ssl_check} ? 0 : 1;
        }
    }

    $self->{ssl_set} = 1;
}

sub _KeyChain_or_KeyStore_Export {
    my ($self) = @_;

    # Only MacOSX and MSWin32 are supported
    return unless $OSNAME =~ /^darwin|MSWin32$/;

    # But we don't need to extract anything if we still use an option to authenticate server certificate
    return if $self->{ca_cert_file} || $self->{ca_cert_dir} || (ref($self->{ssl_fingerprint}) eq 'ARRAY' && @{$self->{ssl_fingerprint}});

    my $logger = $self->{logger};
    my $vardir = $self->{_vardir};
    my $basename = $OSNAME eq 'darwin'  ? "keychain" : "keystore";
    unless (defined($_SSL_ca)) {
        # Just clean up file that could have been created by glpi-agent v1.3
        if ($vardir && -d $vardir) {
            my $obsolete = "$vardir/$basename-export.pem";
            unlink $obsolete if -e $obsolete;
        }
    }

    # Support --ssl-keystore=none option
    return if $self->{ssl_keystore} && $self->{ssl_keystore} =~ /^none$/i;

    # Read certificates are cached for one hour after the service is started
    return $_SSL_ca->{_certs}
        if $_SSL_ca->{_expiration} && time < $_SSL_ca->{_expiration};

    IO::Socket::SSL::Utils->require();

    # Free stored certificates
    IO::Socket::SSL::Utils::CERT_free(@{$_SSL_ca->{_certs}})
        if ref($_SSL_ca->{_certs}) eq 'ARRAY';

    $logger->debug(
        _log_prefix .
        ($_SSL_ca ? "Updating" : "Reading") . " $basename known certificates"
    );

    my @certs = ();

    File::Temp->require();
    if ($EVAL_ERROR) {
        $logger->error("Can't load File::Temp to export $basename certificates");
        return;
    }

    if ($OSNAME eq 'darwin') {
        my $tmpfile = File::Temp->new(
            TEMPLATE    => "$basename-export-XXXXXX",
            DIR         => $vardir,
            SUFFIX      => ".pem",
        );
        my $file = $tmpfile->filename;
        my $store;
        if ($self->{ssl_keystore})  {
            foreach my $case (split(/,+/, $self->{ssl_keystore})) {
                $case = trimWhitespace($case);
                $store .= $case . " "
                    if -e $case;
            }
        }
        getAllLines(
            command => "security find-certificate -a -p $store > '$file'",
            logger  => $logger
        );
        @certs = IO::Socket::SSL::Utils::PEM_file2certs($file)
            if -s $file;
    } else {
        my @certCommands;
        if ($self->{ssl_keystore})  {
            foreach my $case (split(/,+/, $self->{ssl_keystore})) {
                $case = trimWhitespace($case);
                if ($case =~ /^(Service|Enterprise|GroupPolicy|User)?-?(My|CA|Root)$/) {
                    my $store = $2 =~ /CA/i ? "CA" : "Root";
                    my $option = $1 ? " -$1" : "";
                    push @certCommands, "certutil -Silent -Split$option -Store $store";
                } else {
                    $logger->debug("Unsupported ssl-keystore option definition: $case");
                }
            }
        } else {
            @certCommands = (
                "certutil -Silent -Split -Store CA",
                "certutil -Silent -Split -Store Root",
                "certutil -Silent -Split -Enterprise -Store CA",
                "certutil -Silent -Split -Enterprise -Store Root",
                "certutil -Silent -Split -GroupPolicy -Store CA",
                "certutil -Silent -Split -GroupPolicy -Store Root",
                "certutil -Silent -Split -User -Store CA",
                "certutil -Silent -Split -User -Store Root"
            );
        }

        unless (@certCommands) {
            $logger->debug("No keystore to export server certificates from");
            return
        }

        # Windows keystore support
        Cwd->require();
        my $cwd = Cwd::cwd();

        # Create a temporary folder in vardir to cd & export certificates
        my $tmpdir = File::Temp->newdir(
            TEMPLATE    => "$basename-export-XXXXXX",
            DIR         => $vardir,
            TMPDIR      => 1,
        );
        my $certdir = $tmpdir->dirname;
        $certdir =~ s{\\}{/}g;
        if (-d $certdir) {
            $logger->debug2("Changing to '$certdir' temporary folder");
            chdir $certdir;

            foreach my $command (@certCommands) {
                my ($kind, $store) = $command =~ /-Split( -\w+)? -Store (\w+)$/;
                my $storeDirname = $kind && $kind =~ /^ -(\w+)$/ ? "$1-$store" : $store;
                mkdir $storeDirname;
                chdir $storeDirname;
                getAllLines(
                    command => $command,
                    logger  => $logger
                );
                chdir "..";
            }

            # Export certificates from keystore as crt files

            # Convert each crt file to base64 encoded cer file and concatenate in certchain file
            File::Glob->require();
            foreach my $certfile (File::Glob::bsd_glob("$certdir/*/*")) {
                if ($certfile =~ m{/([^/]+/[^/]+\.crt)$}) {
                    getAllLines(
                        command => "certutil -encode $1 temp.cer",
                        logger  => $logger
                    );
                    push @certs, IO::Socket::SSL::Utils::PEM_file2cert("$certdir/temp.cer")
                        if -s "$certdir/temp.cer";
                    unlink "$certdir/temp.cer";
                }
                unlink $certfile;
            }

            # Get back to current dir
            $logger->debug2("Changing back to '$cwd' folder");
            chdir $cwd;
        }
    }

    # Always include default CA file from Mozilla::CA
    if (Mozilla::CA->require()) {
        my $cacert = Mozilla::CA::SSL_ca_file();
        push @certs, IO::Socket::SSL::Utils::PEM_file2certs($cacert)
            if -e $cacert;
    }

    # Update class level datas
    $_SSL_ca->{_expiration} = time + 3600;
    return $_SSL_ca->{_certs} = \@certs;
}

sub compress {
    my ($self, $data) = @_;

    return
        $self->{compression} eq 'zlib' ? Compress::Zlib::compress($data) :
        $self->{compression} eq 'gzip' ? $self->_compressGzip($data)     :
                                         $data;
}

sub uncompress {
    my ($self, $data, $type) = @_;

    if ($type) {
        $type =~ s|^application/||i;
    } else {
        $type = "unspecified";
    }

    if ($type =~ /^x-compress-zlib$/i) {
        $self->{logger}->debug2("format: Zlib");
        return Compress::Zlib::uncompress($data);
    } elsif ($type =~ /^x-compress-gzip$/i) {
        $self->{logger}->debug2("format: Gzip");
        return $self->_uncompressGzip($data);
    } elsif ($type =~ /^json$/i) {
        $self->{logger}->debug2("format: JSON");
        return $data;
    } elsif ($type =~ /^xml$/i) {
        $self->{logger}->debug2("format: XML");
        return $data;
    } elsif ($data =~ /^\s*(\{.*\})\s*$/s) {
        $self->{logger}->debug2("format: JSON detected");
        return $1;
    } elsif ($data =~ /^<\?xml version/) {
        $self->{logger}->debug2("format: XML detected");
        return $data;
    } elsif ($data =~ /(<html><\/html>|)[^<]*(<.*>)\s*$/s) {
        $self->{logger}->debug2("format: Plaintext");
        return $2;
    } else {
        $self->{logger}->debug2("unsupported format: $type");
        return;
    }
}

sub _compressGzip {
    my ($self, $data) = @_;

    File::Temp->require();
    my $in = File::Temp->new();
    print $in $data;
    close $in;

    my $result = getAllLines(
        command => 'gzip -c ' . $in->filename(),
        logger  => $self->{logger}
    );

    return $result;
}

sub _uncompressGzip {
    my ($self, $data) = @_;

    File::Temp->require();
    my $in = File::Temp->new();
    print $in $data;
    close $in;

    my $result = getAllLines(
        command => 'gzip -dc ' . $in->filename(),
        logger  => $self->{logger}
    );

    return $result;
}

sub END {
    # Free eventually stored certificates
    IO::Socket::SSL::Utils::CERT_free(@{$_SSL_ca->{_certs}})
        if ref($_SSL_ca->{_certs}) eq 'ARRAY';
}

1;
__END__

=head1 NAME

GLPI::Agent::HTTP::Client - An abstract HTTP client

=head1 DESCRIPTION

This is an abstract class for HTTP clients. It can send messages through HTTP
or HTTPS, directly or through a proxy, and validate SSL certificates.

=head1 METHODS

=head2 new(%params)

The constructor. The following parameters are allowed, as keys of the %params
hash:

=over

=item I<logger>

the logger object to use (default: a new stderr logger)

=item I<config>

the GLPI::Agent::Config object where to find agent SSL related options

=back

=head2 request($request)

Send given HTTP::Request object, handling SSL checking and user authentication
automatically if needed.
