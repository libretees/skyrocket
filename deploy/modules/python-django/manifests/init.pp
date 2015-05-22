include python3-pip

class python-django {
    exec { 'pip3 install django':
        path => "/usr/bin"
    }
}
