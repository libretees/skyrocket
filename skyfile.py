from sky.api import permanent, ephemeral, infrastructure

@permanent
@infrastructure(environment='test')
def provision():
    print('test')

print('type', type(provision))
