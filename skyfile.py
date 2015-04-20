from sky.api import permanent, ephemeral, infrastructure

@ephemeral
@infrastructure(environment='test')
def provision():
    print('test')

print('type', type(provision))
