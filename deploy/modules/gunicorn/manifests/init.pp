include python3-pip

class gunicorn {
    exec { "pip3 install gunicorn":
        path => "/usr/bin"
    }
}
