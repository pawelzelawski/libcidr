import platform
from setuptools import setup, Extension

defines = [('_POSIX_C_SOURCE', '200809L')]

if platform.system() == 'Linux':
    defines.append(('CIDR_LINUX', None))
elif platform.system() == 'OpenBSD':
    defines.append(('CIDR_OPENBSD', None))

ext = Extension(
    'libcidr',
    sources=[
        'python/_libcidr_ext.c',
        'src/cidr_addr.c',
        'src/cidr_bulk.c',
        'src/cidr_prefix.c',
        'src/cidr_classify.c',
        'src/cidr_index.c',
    ],
    include_dirs=['include'],
    define_macros=defines,
    py_limited_api=True,
    extra_compile_args=['-std=c11', '-O2', '-Wall', '-Wextra'],
)

setup(ext_modules=[ext])
