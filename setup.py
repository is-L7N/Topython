from setuptools import setup, find_packages

setup(
    name='Topython', 
    version='0.3',
    packages=find_packages(),
    install_requires=[
        'requests',
        # لا يمكن تثبيت هذه المكتبات مباشرة لأنها تأتي مع بايثون:
        # 'random',
        # 'uuid',
        # 'secrets',
        # 'json',
        # 'time',
        # 'urllib'
    ],
    author='L7N Iraqi',
    author_email='l7npypi@gmail.com',
    description='Best library to check Instagram applications',
    long_description=open('README.md').read(),  
    long_description_content_type='text/markdown',
    url='https://t.me/Topython',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',  
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)