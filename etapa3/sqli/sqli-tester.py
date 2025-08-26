from aiohttp import ClientTimeout, ClientError, ClientSession
from aiohttp.client import _BaseRequestContextManager
from asyncio import as_completed, CancelledError, create_task, run as async_run
from argparse import ArgumentParser, Namespace
from colorama import Fore, Style
from json import JSONDecodeError, loads
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from os.path import exists
from os import stat
from typing import Callable, cast, Dict, NoReturn, Optional, Tuple, Union
from sys import argv, exit
from user_agent import generate_user_agent
from urllib.parse import quote, urlparse

# Sets Fore class attributes as constants
# You can access all attributes as [F|S]_NAME global constants
#<
# e.g. Fore.RED -> F_RED
for k,v in Fore.__dict__.items():
    globals()[f"F_{k}"] = v

# As previously
# e.g. Style.BRIGHT -> S_BRIGHT
for k,v in Style.__dict__.items():
    globals()[f"S_{k}"] = v
#>

# JSON Schema for tests cases json validation
#<
TESTS_SCHEMA: str = '''
{
    "$schema": "https://json-schema.org/draft/2020-12/schema#",
    "$id": "http://sqli-analizer.py/tests",
    "$defs": {
        "test": {
            "type": "object",
            "properties": {
                "priority": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "title": "The execution priority 1-10"
                },
                "name": {
                    "type": "string",
                    "title": "Test case title"
                },
                "payload": {
                    "type": "string",
                    "title": "Injection payload"
                },
                "expect": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "string"
                    }
                }
            },
            "required": [
                "priority",
                "name",
                "payload",
                "expect"
            ]
        },
        "tests": {
            "type": "array",
            "items": {
                "$ref": "#/$defs/test"
            }
        }
    },
    "type": "object",
    "properties": {
        "priority": {
            "$ref": "#/$defs/tests"
        }
    },
    "required": [ "tests" ]
}'''.strip()
TESTS_SCHEMA = loads(TESTS_SCHEMA)
#>

class SqliTestResult:
    '''A result object for sqli tests.'''
#<
    def __init__(self, expect: list[str]) -> None:
        '''Initializes the instance.'''
        #<
        if len(expect) == 0:
            raise Exception("'expect' param is empty!")

        self.param: str = ''
        self._status_code: int = 0
        self._http_response: str = ''
        self._expect_one_of: list[str] = expect
        self.error: bool = False
        self.is_vulnerable: bool = False
        #>

    # Properties
    #<
    @property
    def status_code(self) -> int:
        '''Gets the status code.'''
        return self._status_code

    @status_code.setter
    def status_code(self, status: int) -> None:
        '''Set status code.'''
        #<
        if status < 100 or status > 599:
            raise Exception("Status out of range (100~599)!")

        self._status_code = status
        #>

    @property
    def http_response(self) -> str:
        '''Gets the http response of the request.'''
        return self._response_body

    @http_response.setter
    def http_response(self, response: str) -> None:
        self._http_response = response
    #>

    def check(self) -> None:
        '''Check the http response searching for expected results.'''
        #<
        if not self.error and len(self._http_response):
            for e in self._expect_one_of:
                if e in self._http_response:
                    self.is_vulnerable = True
                    break
        #>
#>


class TargetUrl:
#<
    def __init__(self, url: str) -> None:
        '''Initializes the instance.'''
        #<
        self.url: str = url
        self._test_results: list[SqliTestResult] = []
        #>

    def add_test_result(self, r: SqliTestResult) -> None:
        '''Adds new test result.'''
        self._test_results.append(r)

    def is_vulnerable(self) -> bool:
        '''Check if this target is vulnerable to Sqli.'''
        #<
        if len(self._test_results) == 0:
            raise Exception("No test results were added yet!")

        r: bool = False
        for t in self._test_results:
            t.check()
            if t.is_vulnerable:
                r = True
                break
        return r
        #>
#>


def error(msg: str, code: int=1, _exit: bool=True) -> NoReturn:
    '''Prints an error message and exit.'''
#<
    msg = f"{F_RED}[Error]{S_RESET_ALL} {msg}"
    print(msg)

    if _exit:
        exit(1)
#>

def info(msg: str) -> None:
    '''Prints an info message.'''
#<
    msg = f"{F_YELLOW}[Info]{S_RESET_ALL} {msg}"
    print(msg)
#>

def read_file(file_path: str) -> Union[Dict, NoReturn]:
    '''Tries to read a file or exit.'''
#<
    # Not found
    if not exists(file_path):
        error(f"File '{file_path}' was not found!")

    # Empty file
    if stat(file_path).st_size == 0:
        error(f"File '{file_path}' is empty!")

    # Rads file
    with open(file_path, 'r') as f:
        return f.read()
#>

async def send(s: ClientSession, r_ctx: SqliTestResult, verb: str, url: str,
    args: Namespace, data: dict={}) -> None:
    '''Sends HTTP request to given url.'''
#<
    # Creates headers
    #<
    h:dict = {
            "Accept": "*/*",
            "Host": urlparse(url).netloc,
            "Referer": url.split("?")[0],
            "User-Agent": generate_user_agent()
        }
    #>

    # Set verb method
    #<
    method = None
    if verb == "GET":
        method = s.get
        method  = cast(ClientSession.get, method)
    elif verb == "POST":
        method  = s.post
        method  = cast(ClientSession.post, method)
    #>

    # Send request
    #<
    try:
        ctx: _BaseRequestContextManager
        if verb == "POST":
            ctx = method(url, headers=h, data=data)
        elif verb == "GET":
            ctx = method(url, headers=h)
        else:
            error(f"Unsupported verb: {verb} for target: {url}", _exit=False)
            return (None, None)

        async with ctx as r:
            r_ctx.status_code = r.status
            r_ctx.http_response = await r.text()
    except CancelledError:
        r_ctx.error = True
        if not args.quiet:
            error("Inyection was cancelled!", _exit=False)
    except Exception as e:
        r_ctx.error = True
        if not args.quiet:
            error(e, _exit=False)
    #>
#>

async def run_tests(tests: list, targets, args: Namespace) -> list[TargetUrl]:
    '''Run tests over targets.'''
#<
    # Priorize tests
    tests = sorted(tests, key=lambda t: t["priority"])

    # Run tests
    #<
    # Async aiohttp session
    async with ClientSession(timeout=ClientTimeout(args.timeout)) as s:
        url_targets: list[TargetUrl] = []
        calls: list[asyncio.Task[sqlitestresult]]= []
        for verb, url, fields in targets:
            if not args.quiet:
                info(f"Testing: {S_BRIGHT}{F_YELLOW}{url}{S_RESET_ALL}")

            # Create target context object
            target: TargetUrl = TargetUrl(url)
            url_targets.append(target)

            # Run tests
            #<
            for t in tests:
                if not args.quiet:
                    info(f"Running test: {t['name']}")
                data: dict = {}
                # Sets POST data
                #<
                if verb == "POST":
                    for f in fields:
                        data[f] = t["payload"]
                #>

                # Sets GET QueryString fields
                #<
                if verb == "GET":
                    url += "?" + "&".join([f"{f}={quote(t['payload'])}" for f in fields])
                #>

                # Create Task
                #<
                rctx: SqliTestResult = SqliTestResult(t["expect"])
                target.add_test_result(rctx)
                calls.append(
                    create_task(
                        send(s, rctx, verb, url, args, data)
                    )
                )
                #>
            #>

        # Check results
        #<
        for task in as_completed(calls):
            await task
        #>

        return url_targets
    #>
#>

async def main():
#<
    # CLI arguments
    #<
    ap = ArgumentParser(
            add_help = True,
            description="Modulo 5 - Lección 7 - Actividad 1: " \
            "Automatización de Pruebas de SQL Injection sobre URLs"
        )
    ap.add_argument(
            "-t",
            "--tests",
            action="store",
            dest="tests",
            help="Casos de uso para testear SQLi.",
            required=True
        )
    ap.add_argument(
            "-u",
            "--urls-file",
            action="store",
            dest="targets",
            help="Endpoints a ser testados",
            required=True
        )
    ap.add_argument(
            "--timeout",
            action="store",
            dest="timeout",
            help="Configura el tiempo de espera de las solicitudes",
            default=10
        )
    ap.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            dest="quiet",
            help="Suprime las salidas del testing y solo muestra el reporte."
        )
    args = ap.parse_args()
    #>

    # Check files
    #<
    if not exists(args.tests):
        error(f"File '{args.tests}' was not found!")

    if not exists(args.targets):
        error(f"File '{args.targets}' was not found!")
    #>

    # Reads tests & targets
    tests: str = read_file(args.tests)
    targets: list[str] = read_file(args.targets).split('\n')

    # Try to decode tests as json
    #<
    try:
        tests = loads(tests)

        # Validate tests cases file
        validate(tests, TESTS_SCHEMA)
    except JSONDecodeError as e:
        error(f"Can't decode '{args.tests}' file as json: {e.msg}")
    except ValidationError as e:
        error(f"Error at '{args.tests}': {e.message}")
    #>

    # Targets processing
    # Target estructure: VERB URL FIELD FIELD ...
    #<
    # Remove empty/commented lines
    targets = list(filter(lambda t: len(t) > 1 and t[0] != "#", targets))

    for i in range(len(targets)):
        t: str = targets[i]

        # Skip comment
        #<
        if t[0] == "#":
            continue
        #>

        # Process target
        #<
        elements: list[str] = t.split(" ")

        # Invalid target (at least 3 items VERB URL FIELD)
        #<
        if len(elements) < 3:
            info(f"Invalid target (skip): {t}")
        #>

        verb: str = elements[0]
        url: str = elements[1]
        fields = elements[2:]

        # Make the target structure
        targets[i] = (verb, url, fields)
        #>
    #>

    # Tests processing
    targets: list[TargetUrl] = await run_tests(tests["tests"], targets, args)

    # Print report
    #<
    report = f"\n{F_YELLOW}{S_BRIGHT}Report:{S_RESET_ALL}\n"
    for t in targets:
        report += f"{F_YELLOW}URL:{S_RESET_ALL} {t.url}\n"
        is_vulnerable = f"{F_RED}Yes" if t.is_vulnerable() else f"{F_GREEN}No"
        report += f"- Vulnerable?: {S_BRIGHT}{is_vulnerable}{S_RESET_ALL}\n"
    print(report)
    #>
#>

if __name__ == '__main__':
    #<
    try:
        async_run(main())
    except KeyboardInterrupt:
        error("Aborted!")
    #>
