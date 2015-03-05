#!/bin/sh
set -e -x

apt-get --yes --quiet update
apt-get --yes --quiet install awscli

aws s3 cp --region $region s3://$s3bucket/$s3object $s3object
