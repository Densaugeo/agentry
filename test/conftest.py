import os


def pytest_addoption(parser):
    parser.addoption(
        '--server', action='store', default='each', choices=['once', 'each'],
        help='`each` to spawn a new server for each test, `once` to spawn a '
            'single server instance for the whole run. Default: `each`.',
    )

def pytest_sessionstart(session):
    os.chdir('test')

def pytest_runtest_setup(item):
    print()

def pytest_runtest_teardown(item):
    print()
