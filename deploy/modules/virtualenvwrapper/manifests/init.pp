include python3-pip

class virtualenvwrapper {
    exec { 'pip3 install virtualenvwrapper':
        path => '/usr/bin'
    }

    file { '/srv/.virtualenvs':
        ensure => directory,
        group => 'ubuntu',
        owner => 'ubuntu'
    }

    file { '/home/ubuntu/.profile':
        ensure => file
    }

    exec { "echo 'export PYTHONPATH=$PYTHONPATH:/usr/local/lib/python3.4/dist-packages' >> /home/ubuntu/.profile":
        path => '/bin'
    }

    exec { "echo 'export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3' >> /home/ubuntu/.profile":
        path => '/bin'
    }

    exec { "echo 'export WORKON_HOME=/srv/.virtualenvs' >> /home/ubuntu/.profile":
        path => '/bin'
    }
    
    exec { "echo 'source /usr/local/bin/virtualenvwrapper.sh' >> /home/ubuntu/.profile":
        path => '/bin'
    }
}
