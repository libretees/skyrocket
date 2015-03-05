#!/bin/sh
set -e -x

apt-get --yes --quiet update
apt-get --yes --quiet install awscli puppet-common

aws s3 cp --region $region s3://$s3bucket/$s3object $s3object
aws s3 cp --region $region s3://$s3bucket/$s3object2 $s3object2

tar xf $s3object2 --directory /etc/puppet
puppet apply /etc/puppet/manifests/init.pp