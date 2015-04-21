from sky.api import permanent, ephemeral, infrastructure

@infrastructure(environment='test', requires=['network', 'database', 'application', 'api'])
def cloud():
    print('make all')

@permanent
@infrastructure(environment='test')
def network():
    print('make network')

@permanent
@infrastructure(environment='test', requires=['network'])
def database():
    print('make database')

@ephemeral
@infrastructure(environment='test', requires=['network', 'database'])
def application():
    print('make application')

@ephemeral
@infrastructure(environment='test', requires=['network', 'database'])
def api():
    print('make api')
