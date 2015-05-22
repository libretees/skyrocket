include python3-pip

class virtualenv {
    exec { 'pip3 install virtualenv':
        path => '/usr/bin'
    }
}
