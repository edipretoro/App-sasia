#!/usr/bin/env perl

use strict;
use warnings;

use Project::Libs;
use App::getmacip;

App::getmacip->new_with_options->run();
