class nginx {
    package { 'nginx':
        ensure  => installed,
    }

    file { '/etc/nginx/nginx.conf':
        ensure  => file,
        content => template("nginx/nginx.conf"),
        require => Package['nginx'],
        notify  => Service['nginx'],
    }

    file { '/etc/nginx/sites-available/default':
        ensure  => file,
        content => template("nginx/nginx-app-proxy"),
        require => Package['nginx'],
        notify  => Service['nginx'],
    }

    file { '/etc/nginx/conf.d/realip.conf':
        ensure  => file,
        content => template("nginx/realip.conf"),
        require => Package['nginx'],
        notify  => Service['nginx'],
    }

    file { '/usr/share/nginx/www':
        ensure  => directory,
        source  => '/etc/puppet/private/www',
        recurse => true,
        require => Package['nginx'],
        before  => Service['nginx'],
    }

    service { 'nginx':
        ensure  => running,
        enable  => true,
    }
}
