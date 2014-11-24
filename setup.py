# coding=utf-8
from distutils.core import setup


def get_dependencies():
    dep_list = []
    with open('requirements.txt', 'r') as deps_file:
        dependency = deps_file.readline().rstrip('\n')
        while dependency:
            dep_list.append(dependency)
            dependency = deps_file.readline().rstrip('\n')
        return dep_list


setup(
    name='crypto_SHUP_algorithm',
    version='0.1',
    packages=['algorithm'],
    url='https://github.com/xSAVIKx/crypto_SHUP_algorithm',
    license='MIT',
    author='Iurii Sergiichuk',
    author_email='iurii.sergiichuk@gmail.com',
    description='Implementation of crypto algorithm SHUP("ШУП", русский). University task.',
    requires=get_dependencies()
)
