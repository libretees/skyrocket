include python-pip
include python3-pip
include virtualenv
include virtualenvwrapper

class application {
    file { '/srv/www':
        ensure => directory,
        group => 'ubuntu', 
        owner => 'ubuntu',
    }

    exec { 'mkvirtualenv www':
        command => "bash --login -c 'source /home/ubuntu/.profile && mkvirtualenv --python=/usr/bin/python3 www'",
        path => ['/bin', '/usr/bin', '/usr/local/bin'],
        user => ubuntu,
        cwd => '/srv/www',
        notify  => [Exec['pip install django'], Exec['pip install gunicorn']],
    }

    exec { 'pip install django':
        command => "bash --login -c 'source /home/ubuntu/.profile && workon www && pip install django'",
        path => ['/bin', '/usr/bin', '/usr/local/bin'],
        user => ubuntu,
        require => Exec['mkvirtualenv www'],
        notify => Exec['django-admin startproject app'],
    }

    exec { 'pip install gunicorn':
        command => "bash --login -c 'source /home/ubuntu/.profile && workon www && pip install gunicorn'",
        path => ['/bin', '/usr/bin', '/usr/local/bin'],
        user => ubuntu,
        require => Exec['mkvirtualenv www'],
        notify => Exec['gunicorn wsgi:application'],
    }

    exec { 'django-admin startproject app':
        command => "bash --login -c 'source /home/ubuntu/.profile && workon www && django-admin startproject app'",
        path => ['/bin', '/usr/bin', '/usr/local/bin'],
        user => ubuntu,
        cwd => '/srv/www',
        require => Exec['pip install django'],
        notify => File['/srv/www/app/gunicorn.conf.py'],
    }

    file { '/srv/www/app/gunicorn.conf.py':
        ensure  => file,
        content => template("application/gunicorn.conf.py"),
        require => Exec['django-admin startproject app'],
        notify => Exec['gunicorn wsgi:application']
    }

    exec { 'gunicorn wsgi:application':
        command => "bash --login -c 'source /home/ubuntu/.profile && workon www && gunicorn --daemon app.wsgi:application'",
        path => ['/bin', '/usr/bin', '/usr/local/bin'],
        user => www-data,
        cwd => '/srv/www/app',
        require => [Exec['pip install gunicorn'], File['/srv/www/app/gunicorn.conf.py']],
    }
}
