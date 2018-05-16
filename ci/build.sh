#!/bin/bash
# Simple build script
bundle install
bundle exec rake vendor
bundle exec rspec spec
