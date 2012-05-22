#!/usr/bin/perl -w
# vim: ts=8 sts=4 sw=4 et :
use strict;
use warnings;
use diagnostics;

use Getopt::Std;
use JSON::PP;
use LWP::UserAgent;
use MIME::Base64;

#--------------------------------------------------------------------------
# Utility for Tiny-Tiny-RSS:
# Un-mark published entries using the API.
# Demonstrates API usage from Perl.
#
# Gregory Margo
# gmargo _at_ yahoo _dot_ com
#
# unmark_published: Unmark published articles in Tiny-Tiny-RSS using the API.
# Copyright (C) 2012  Gregory H. Margo
# License: GPLv2 or later.  See bottom of file for info.
#--------------------------------------------------------------------------

sub Usage
{
    print "$0 -u userid -p password URL\n";
    print "$0 -s sid URL\n";
    print "    -u: User ID\n";
    print "    -p: Password\n";
    print "    -s: Session ID\n";
    print " Provide either userid and password for a new session,\n";
    print " or a session id to use an existing session.\n";
    print " The URL should point to Tiny-Tiny-RSS's API interface,\n";
    print " i.e. \"http://example.com/tt-rss/api/\"\n";
    exit 1;
}

#--------------------------------------------------------------------------
# Command line processing.
our ($opt_u, $opt_p, $opt_s) = ("","","");
Usage() unless getopts('u:p:s:');
Usage() unless (($opt_u ne "" && $opt_p ne "" && $opt_s eq "")      # Supply userid/password
             || ($opt_u eq "" && $opt_p eq "" && $opt_s ne ""));    # or session id.
Usage() unless $#ARGV == 0;                                         # Supply api URL.
my $url = $ARGV[0];

#--------------------------------------------------------------------------
# Globals for message processing.
my $ua = LWP::UserAgent->new();

#--------------------------------------------------------------------------
# Pass in a location and a json hash.
# Fetch and return the decoded response.
sub fetch_json
{
    my ($loc, $jsonHash) = @_;
    my $json_text = encode_json($jsonHash);
    my $response = $ua->post($url, Content => $json_text);
    die("$loc POST error: ".$response->status) if !$response->is_success;
    my $resp = decode_json($response->decoded_content);
    die("$loc Error: ".$resp->{content}->{error}) if $resp->{status} != 0;
    return $resp;
}

#--------------------------------------------------------------------------
# Login if needed.
if ($opt_u ne "")
{
    my $encoded_password = encode_base64($opt_p);   # doesn't really hide anything
    my $resp = fetch_json("Login", {op => 'login', user => $opt_u, password => $encoded_password});
    $opt_s = $resp->{content}->{session_id};
    print "Session ID = $opt_s\n";
}

#--------------------------------------------------------------------------
# Check the SID value if not just logging in.
if ($opt_u eq "")
{
    my $resp = fetch_json("CheckSID", {sid => $opt_s, op => "isLoggedIn"});
    if (! $resp->{content}->{status})
    {
        print "Session ID check FAILED, not logged in\n";
        exit 2;
    }
}

#--------------------------------------------------------------------------
# Just a few experiments.
if (0)
{
    my $resp = fetch_json("getVersion", {sid => $opt_s, op => "getVersion"});
    print "Version = ".$resp->{content}->{version}."\n";
}
if (0)
{
    # Don't use fetch_json() since status!=0 is valid for getApiLevel.
    my $json_text = encode_json({sid => $opt_s, op => "getApiLevel"});
    my $response = $ua->post($url, Content => $json_text);
    die("getApiLevel POST error: ".$response->status) if !$response->is_success;
    my $resp = decode_json($response->decoded_content);

    if ($resp->{status} != 0)
    {
        print "This version does not support 'getApiLevel'\n";
    }
    else
    {
        print "ApiLevel = ".$resp->{content}->{level}."\n";
    }
}
if (0)
{
    my $resp = fetch_json("getUnread", {sid => $opt_s, op => "getUnread"});
    print "Unread = ".$resp->{content}->{unread}."\n";
}

#--------------------------------------------------------------------------
# Unpublish articles
if (1)
{
    # Process the published articles in groups.
    # (limit defaults to 60 but has no "unlimited" setting)

    my $total_unpublished = 0;
    my $donthang = 1000;    # Just in case, don't really use an infinite loop.
    while ($donthang--)
    {
        my $resp = fetch_json("getHeadlines", {sid => $opt_s, op => "getHeadlines",
            feed_id => -2,      # -2 == published
            limit => 60,
            is_cat => JSON::PP::false,
            show_excerpt => JSON::PP::false,
            show_content => JSON::PP::false,
            view_mode => "all_articles",
            include_attachments => JSON::PP::false});

        # Loop through the array to build a list of article ids.
        my @published_articles;
        push @published_articles, $_->{id} foreach @{$resp->{content}};

        # Unpublish a block of articles.
        if (@published_articles)
        {
            my $id_list = join(",", @published_articles);
            my $resp = fetch_json("updateArticle", {sid => $opt_s, op => "updateArticle",
                article_ids => "$id_list",
                mode => 0,      # mode 0 == set to false
                field => 1});   # field 1 == published
            warn("updateArticle Problem: status = ".$resp->{content}->{status}." for article_ids=$id_list")
                if $resp->{content}->{status} ne "OK";
            #print "Cleared ".@published_articles." published articles this pass\n";
            $total_unpublished += @published_articles;
        }
        else
        {
            last;  # No more published articles.
        }
    }
    print "Cleared $total_unpublished published articles\n";
}

exit 0;

# GPL V2 disclosure:
#
# unmark_published: Unmark published articles in Tiny-Tiny-RSS using the API.
# Copyright (C) 2012  Gregory H. Margo
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
