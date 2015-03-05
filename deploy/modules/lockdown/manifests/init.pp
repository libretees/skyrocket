class lockdown {
    stage { 'first': before => Stage['main'] }
    class { lockdown_first: stage => 'first' }
}

class lockdown_first {
    file { "/etc/puppet/.git":
        ensure  => directory,
        mode    => '700',
    }

    file { "/etc/puppet/private":
        ensure  => directory,
        mode    => '700',
    }

    file { "/etc/init/disable-ec2-metadata.conf":
        ensure  => file,
        content => template("lockdown/disable-ec2-metadata.conf"),
    }

    exec { "/sbin/start disable-ec2-metadata":
        require => File["/etc/init/disable-ec2-metadata.conf"],
    }
}
