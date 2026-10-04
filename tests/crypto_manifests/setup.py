from setuptools import setup
setup(
    name="demo",
    install_requires=[
        "requests>=2.0",
        "pycryptodome==3.20",
        'cryptography; python_version > "3"',
    ],
    extras_require={"fast": ["argon2-cffi"], "dev": ["pytest"]},
)
