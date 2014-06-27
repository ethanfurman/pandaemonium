from distutils.core import setup
from glob import glob
import os

long_desc = open('pandaemonium.README').read()

setup( name='pandaemonium',
       version= '0.5.0',
       license='BSD License',
       description='Framework for writing daemons, with API similar to threading and multiprocessing.',
       long_description=long_desc,
       py_modules=['pandaemonium'],
       provides=['pandaemonium'],
       author='Ethan Furman',
       author_email='ethan@stoneleaf.us',
       classifiers=[
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: BSD License',
            'Natural Language :: English',
            'Operating System :: POSIX',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2.6',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3',
            'Topic :: Software Development',
            ],
    )


