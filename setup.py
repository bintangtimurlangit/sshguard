"""Setup configuration for SSHGuard package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / 'README.md'
long_description = readme_file.read_text() if readme_file.exists() else ''

# Read requirements
requirements_file = Path(__file__).parent / 'requirements.txt'
requirements = []
if requirements_file.exists():
    requirements = requirements_file.read_text().strip().split('\n')

setup(
    name='sshguard',
    version='1.0.0',
    description='LSTM-based SSH intrusion detection system',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='SSHGuard Team',
    author_email='',
    url='https://github.com/yourusername/SSHGuard',
    license='MIT',
    
    packages=find_packages(),
    
    install_requires=requirements,
    
    python_requires='>=3.8',
    
    scripts=['scripts/sshguard'],
    
    include_package_data=True,
    
    package_data={
        'sshguard': [],
    },
    
    data_files=[
        ('share/sshguard/models', [
            'models/lstm_model.keras',
            'models/scaler.pkl',
            'models/label_encoder.pkl'
        ]),
        ('etc/sshguard', ['config/sshguard.conf']),
    ],
    
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
    ],
    
    keywords='ssh security intrusion-detection lstm machine-learning',
)

