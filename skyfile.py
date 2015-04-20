from sky.api import permanent, ephemeral, infrastructure

@infrastructure(environment='test')
@ephemeral
def provision():
    print('test')
