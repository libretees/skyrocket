from sky.api import permanent, ephemeral, infrastructure

@permanent
@infrastructure(environment='test')
def provision():
    print('test')

@ephemeral
@infrastructure(environment='test', depends=['provision', 'setup'])
def provision2():
    print('test')