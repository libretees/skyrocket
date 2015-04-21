from sky.api import permanent, ephemeral, infrastructure
import test

@ephemeral
@infrastructure(environment='test')
def provision():
    print('test')
