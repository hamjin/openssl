#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use TLSProxy::Message;
use TLSProxy::Record;
use Cwd qw(abs_path);

my $test_name = "test_tls13drafts";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the module feature enabled"
    if disabled("module");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs TLS1.3 enabled"
    if disabled("tls1_3") || (disabled("ec") && disabled("dh"));

$ENV{OPENSSL_MODULES} = abs_path(bldtop_dir("test"));

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

use constant {
    CHECK_CLIENT_OFFER => 0,
    SERVER_DRAFT_ONLY => 1,
    CLIENT_ACCEPTS_DRAFT => 2,
    HRR_DRAFT_ONLY => 3,
};

my @drafts = (
    TLSProxy::Record::VERS_TLS_1_3_DRAFT_23(),
    TLSProxy::Record::VERS_TLS_1_3_DRAFT_26(),
    TLSProxy::Record::VERS_TLS_1_3_DRAFT_27(),
    TLSProxy::Record::VERS_TLS_1_3_DRAFT_28(),
);

my $saw_client_offer = 0;
my $saw_hrr_draft = 0;

$proxy->filter(make_draft_filter(CHECK_CLIENT_OFFER, undef,
                                 \$saw_client_offer, \$saw_hrr_draft));
$proxy->clientflags("-no_rx_cert_comp");
$proxy->start() or plan skip_all => "Unable to start up Proxy for tests";
plan tests => 13;
ok($saw_client_offer, "ClientHello offers TLS 1.3 draft versions");

foreach my $draft (@drafts) {
    $proxy->clear();
    $proxy->filter(make_draft_filter(SERVER_DRAFT_ONLY, $draft,
                                     \$saw_client_offer, \$saw_hrr_draft));
    $proxy->clientflags("-no_rx_cert_comp");
    $proxy->start();
    ok(TLSProxy::Message->success(),
       sprintf("Server accepts TLS 1.3 draft 0x%04x", $draft));
}

foreach my $draft (@drafts) {
    $proxy->clear();
    $proxy->filter(make_draft_filter(CLIENT_ACCEPTS_DRAFT, $draft,
                                     \$saw_client_offer, \$saw_hrr_draft));
    $proxy->clientflags("-no_rx_cert_comp");
    $proxy->start();
    ok(TLSProxy::Message->success(),
       sprintf("Client accepts TLS 1.3 draft 0x%04x", $draft));
}

SKIP: {
    skip "No EC support in this OpenSSL build", scalar(@drafts) if disabled("ec");

    foreach my $draft (@drafts) {
        $saw_hrr_draft = 0;
        $proxy->clear();
        $proxy->filter(make_draft_filter(HRR_DRAFT_ONLY, $draft,
                                         \$saw_client_offer, \$saw_hrr_draft));
        $proxy->clientflags("-no_rx_cert_comp");
        $proxy->serverflags("-no_rx_cert_comp -curves P-384");
        $proxy->start();
        ok(TLSProxy::Message->success() && $saw_hrr_draft,
           sprintf("HRR echoes TLS 1.3 draft 0x%04x", $draft));
    }
}

sub get_supported_versions
{
    my $message = shift;
    my $ext = $message->extension_data->{TLSProxy::Message::EXT_SUPPORTED_VERSIONS};

    return () if !defined $ext;

    if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
        return () if length($ext) < 1;
        my $len = unpack("C", substr($ext, 0, 1));
        return unpack("n*", substr($ext, 1, $len));
    }

    return unpack("n", $ext);
}

sub set_supported_versions
{
    my $message = shift;
    my @versions = @_;
    my $ext;

    die "No supported_versions supplied\n"
        if scalar @versions == 0 || grep { !defined $_ } @versions;

    if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
        $ext = pack("C", 2 * scalar @versions) . pack("n*", @versions);
    } else {
        $ext = pack("n", $versions[0]);
    }

    $message->set_extension(TLSProxy::Message::EXT_SUPPORTED_VERSIONS, $ext);
    $message->repack();
}

sub make_draft_filter
{
    my ($testtype, $draft, $saw_client_offer_ref, $saw_hrr_draft_ref) = @_;

    return sub {
        my $proxy = shift;

        return if scalar @{$proxy->message_list} == 0;

        foreach my $message (@{$proxy->message_list}) {
            next if scalar @{$message->records} == 0;
            next if ${$message->records}[0]->flight != $proxy->flight;
            next if $message->mt != TLSProxy::Message::MT_CLIENT_HELLO
                    && $message->mt != TLSProxy::Message::MT_SERVER_HELLO;

            if ($testtype == CHECK_CLIENT_OFFER) {
                next if $message->mt != TLSProxy::Message::MT_CLIENT_HELLO;
                my %seen = map { $_ => 1 } get_supported_versions($message);
                ${$saw_client_offer_ref} =
                    $seen{TLSProxy::Record::VERS_TLS_1_3_DRAFT_23()}
                    && $seen{TLSProxy::Record::VERS_TLS_1_3_DRAFT_26()}
                    && $seen{TLSProxy::Record::VERS_TLS_1_3_DRAFT_27()}
                    && $seen{TLSProxy::Record::VERS_TLS_1_3_DRAFT_28()};
                return;
            }

            if ($testtype == CLIENT_ACCEPTS_DRAFT) {
                next if $message->mt != TLSProxy::Message::MT_SERVER_HELLO;
                set_supported_versions($message, $draft);
                return;
            }

            if ($testtype == SERVER_DRAFT_ONLY || $testtype == HRR_DRAFT_ONLY) {
                if ($message->mt == TLSProxy::Message::MT_CLIENT_HELLO) {
                    set_supported_versions($message, $draft);
                    return;
                }

                if ($testtype == HRR_DRAFT_ONLY
                        && $message->mt == TLSProxy::Message::MT_SERVER_HELLO) {
                    my ($version) = get_supported_versions($message);
                    ${$saw_hrr_draft_ref} =
                        (defined $version && $version == $draft);
                    return;
                }
            }
        }
    };
}
