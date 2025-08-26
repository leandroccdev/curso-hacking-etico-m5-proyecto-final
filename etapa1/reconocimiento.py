# Imports zone
from __future__ import annotations
from argparse import ArgumentParser, Namespace
from bs4 import BeautifulSoup
from bs4.element import ResultSet
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from datetime import datetime
from json import dump
from os.path import basename, exists
from os import mkdir, stat, urandom
from requests import get
from requests.exceptions import RequestException
from string import ascii_letters, digits
from types import FrameType
from typing import (
        cast,
        Callable,
        Dict,
        Iterator,
        List,
        NoReturn,
        Optional,
        Tuple,
        Union
    )
from user_agent import generate_user_agent
from urllib.parse import ParseResult, ParseResultBytes, quote, urlparse
from sys import argv
import ssdeep
import logging
import signal

MANUALLY_ABORTED: bool = False
NOW = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

# Sets Fore class attributes as constants
# You can access all attributes as [F|S]_NAME global constants
# e.g. Fore.RED -> F_RED
for k,v in Fore.__dict__.items():
    globals()[f"F_{k}"] = v

# As previously
# e.g. Style.BRIGHT -> S_BRIGHT
for k,v in Style.__dict__.items():
    globals()[f"S_{k}"] = v

# Setup log dir
LOG_DIR: str = "log/"
# Create log dir
if not exists(LOG_DIR):
    mkdir(LOG_DIR)

# Setup logging module
log_file: str = f"{LOG_DIR}{NOW}_{basename(argv[0])}.log"
logging.basicConfig(
        filename=log_file,
        format=f"[%(asctime)s][%(levelname)s][%(name)s] %(message)s",
        level=logging.DEBUG
    )
logger = logging.getLogger("main")
logger.setLevel(logging.DEBUG)

# Disables for modules
for l in [
        "urllib3.connectionpool"
    ]:
    logging.getLogger(l).setLevel(logging.ERROR)

class IgnoreKeyboardInterrupt:
    '''Ignore SIGINT inside context manager.'''
    def __init__(self) -> None:
        '''Initialices the instance.'''
        self._signal_received: Union[bool, Tuple] = False
        self._handler: Callable

    def __enter__(self) -> IgnoreKeyboardInterrupt:
        logger.debug("Entered a protected context")
        self._signal_received = False
        self._handler = signal.signal(signal.SIGINT, self._handler_fn)
        return self

    def _handler_fn(self, sig: int, frame: FrameType) -> None:
        '''Handles a clean exit for SIGINT (Ctrl+C -> KeyboardInterrupt) signal.'''
        global MANUALLY_ABORTED
        self._signal_received = (sig, frame)
        MANUALLY_ABORTED = True
        print()
        info("Performing clean exit, please wait…")

    def __exit__(self, exc_type, value, traceback) -> None:
        logger.debug("Exited a protected context")
        signal.signal(signal.SIGINT, self._handler_fn)
        if self._signal_received:
            self._handler_fn(*self._signal_received)

    def is_sigint(self) -> None:
        '''Indicates if SIGINT (Ctrl+C) signal was triggered.'''
        return self._signal_received != False


class DiscoveredURL:
    '''Represents a discovered URL that has already been queried.'''
    def __init__(self, url: str, status_code: int, headers: dict, content: str
            ) -> None:
        '''Initializes the instance.'''
        self.url: str = url
        self.status_code: int = status_code
        self.headers: dict = headers
        self.content: str = content


def error(msg: str, terminate=True) -> Optional[NoReturn]:
    '''Prints a message an terminate program.'''
    print(f"{S_BRIGHT}{F_RED}[Error]{S_RESET_ALL} {msg}")

    if terminate:
        exit(1)

def info(msg: str) -> None:
    '''Prints an info message.'''
    print(f"{S_BRIGHT}{F_YELLOW}[Info]{S_RESET_ALL} {msg}")

def read_file(file_path: str) -> Union[Dict, NoReturn]:
    '''Tries to read a file or exit.'''
    # Not found
    if not exists(file_path):
        logger.error("File not found at {file_path}")
        error(f"File '{file_path}' was not found!")

    # Empty file
    if stat(file_path).st_size == 0:
        logger.error(f"Empty file: {file_path}")
        error(f"File '{file_path}' is empty!")

    # Rads file
    logger.debug(f"Reading file {file_path}")
    with open(file_path, 'r') as f:
        return f.read()

def send_get(url: str, timeout=10) -> Optional[Tuple[str, int, dict, str]]:
    '''Performs a GET.

    Returns: Tuple with:
        - URL
        - HTTP Status Code
        - Headers as dict
        - HTML Content
    '''
    global MANUALLY_ABORTED

    # Aborts this tasks before it starts when ^C was detected
    if MANUALLY_ABORTED:
        logger.debug(f"Aborted GET: {url}")
        return None

    #info(f"Quering '{url}'")
    logger.debug(f"Quering: '{url}'")

    # Creates headers
    parsed_url = urlparse(url)
    h:dict = {
            "Accept": "*/*",
            "Host": parsed_url.netloc,
            "Referer": f"{parsed_url.scheme}://{parsed_url.netloc}",
            "User-Agent": generate_user_agent()
        }
    logger.debug("Headers: " + str(h))

    try:
        with get(url, headers=h, timeout=timeout) as r:
            logger.debug(f"HTTP CODE: {r.status_code}")
            return (url, r.status_code, dict(r.headers), r.text)
    except RequestException as e:
        logger.error(str(e))

def analize_forms(html: str) -> Optional[Dict]:
    '''Analizes and extracts all forms from an html document.'''
    # Empty HTML
    if not html:
        logger.error("Empty html was given!")
        return None

    info(f"Analyzing forms...")

    soup:BeautifulSoup = BeautifulSoup(html, 'lxml')
    ftarget_attrs: List = [
            'action',
            'enctype',
            'id',
            'method',
            'name',
            'novalidate'
        ]
    etarget_attrs: List = ['id', 'name', 'type', 'value']

    rs_forms: ResultSet = soup.find_all('form')
    # No forms found
    if not rs_forms:
        logger.debug("No forms found!")
        info(f"{F_YELLOW}No forms were found!{S_RESET_ALL}")

    # loop through forms
    forms: List = []
    for f in rs_forms:
        # Print all forms attributes
        print(f"\n{F_YELLOW}Form attributes:{S_RESET_ALL}")

        logger.debug("Form Attributes:")
        form: dict = { "attributes": [], "elements": [] }
        for fname,fvalue in f.attrs.items():
            # Avoids unimportant attrs
            if fname not in ftarget_attrs:
                continue

            # Converts list into strings
            if isinstance(fvalue, list):
                fvalue = " ".join(fvalue)

            logger.debug(f"- {fname}: {fvalue}")
            form["attributes"] = { fname: fvalue }
            print(f"- {Fore.RED}{fname}: {Style.RESET_ALL}{fvalue}")

        # Extract form elements
        elements_to_find = [
                'a',
                'input',
                'textarea',
                'select',
                'button'
            ]
        rs_elements: ResultSet = f.find_all(elements_to_find)
        logger.debug("Searching for subform elements: " + ", ".join(elements_to_find))

        # loop through elements
        elements: List[Dict] = []
        for e in rs_elements:
            # Print all elements attributes
            element: Dict = {"attributes": [], "type": e.name}
            logger.debug(f"Element: {e.name}")
            print(f"Element: {F_YELLOW}{e.name.capitalize()} {S_RESET_ALL}")

            # Filter the subform element's attributes by etarget_attrs
            e_attrs: List = list(filter(
                    lambda _e: _e[0] in etarget_attrs,
                    e.attrs.items()
                ))

            # Process the subform element's attributes
            if e_attrs:
                print(f"Attributes:")

                for ename,evalue in e_attrs:
                    # Converts list into strings
                    if isinstance(evalue, list):
                        evalue = " ".join(evalue)

                    logger.debug(f"- {ename}: {evalue} ")
                    element["attributes"].append({ename: evalue})
                    print(f"- {F_YELLOW}{ename}:{S_RESET_ALL} {evalue}")

            # Save element
            elements.append(element)

        # Save form's elements
        form["elements"] = elements

        # Save form
        forms.append(form)

    return forms

def analize_headers(headers: dict) -> Optional[Dict]:
    '''Analizes and extract relevant headers from a headers list.'''
    headers_to_analize: List[str] = [
            "server",
            "x-powered-by",
            "set-cookie",
            "content-type",
            "content-security-policy",
            "x-frame-options",
            "strict-transport-security",
            "access-control-allow-origin",
            "referrer-policy",
            "cache-control",
            "etag",
            "date",
            "last-modified"
        ]
    relevant_headers: Dict = {
            k: v
            for k,v in headers.items()
            if k.lower() in headers_to_analize
        }
    info(f"{F_YELLOW}")
    return relevant_headers

def detect_error_page(base_url: str) -> List[str]:
    '''Performs a error page detection using fuzzy hash.'''
    # Generates random error urls
    info("Generating random error capable URLs")
    # Generates a error capable URL that doesn't exists
    random_payload_len: int = 20 
    allowed_chars: List[int] = [ord(c) for c in ascii_letters + digits]
    fuzzy_hashes: List[str] = []

    # Generates fuzzy hashes
    for _ in range(10):
        r_url: str = f"{base_url}"

        # Generate de capable random URL
        i: int = 0
        while i <= random_payload_len:
            c: int = ord(urandom(1))
            if c not in allowed_chars:
                continue
            else:
                r_url += chr(c)
                i += 1

        result = send_get(r_url)

        # Avoids process the current element when result is None
        if result == None:
            error(f"Some error happens for attempt: {_}", terminate=False)
            continue

        url, status, headers, content = result
        # Generate fuzzy hash
        fuzzy_hashes.append(ssdeep.hash(f"{status}{content}"))

        del url
        del status
        del headers
        del content
        del r_url

    # Empty error data
    if not fuzzy_hashes:
        error("Can't detect error pages!")

    return fuzzy_hashes

def is_error_page(err_data: List[str], fhash: str, umbral: int = 90) -> bool:
    '''Detects an error page based on it's fuzzy hash.'''
    # Compares al elements as combinated product
    scores: List[int] = [ssdeep.compare(e, fhash) for e in err_data]
    return (sum(scores) / len(scores)) > umbral

def discover_urls(base_url: str, iurls: Iterator[str], timeout:int,
        err_data: List[str], workers: int=1) -> List[DiscoveredURL]:
    '''Perform a search for discover hidden URLs.'''
    # Create threadpool
    info("Discovering URLs...")

    # Fix base_url
    if base_url[-1] != '/':
        base_url += '/'

    # Discovered URLs
    discovered_urls: List[DiscoveredURL] = []

    logger.debug("Creating threadpool with {workers} workers")
    with IgnoreKeyboardInterrupt() as iki, \
            ThreadPoolExecutor(max_workers=workers) as executor:
        # Adds the tasks to the pool
        logger.debug("Loading tasks into the thread pool...")
        futures: List[Future] = []

        # Adds base URL task
        futures.append(executor.submit(send_get, base_url, timeout))

        for _path in iurls:
            # Aborts the tasks loading process
            if iki.is_sigint():
                logger.debug("Task loading was abborted!")
                break

            # Adds tasks to the thread pool
            futures.append(
                    executor.submit(
                        send_get,
                        f"{base_url}{_path.strip()}",
                        timeout
                    )
                )

        # Aborted by user
        # Returns an empty list
        if iki.is_sigint():
            logger.debug("Aborted by user, returning an empty list!")
            return discovered_urls

        # Collects completed tasks
        for future in as_completed(futures):
            # When the user manually aborts, the loop breaks here
            if iki.is_sigint():
                logger.debug("The completed tasks collection was manually aborted!")
                break

            result: Optional[Tuple[int, dict, str]] = future.result()

            # If result is None, an error happened so
            # Ignores None objects
            if result == None:
                continue

            # When comes here is a valid request
            url, status, headers, content = result # type: ignore
            url = cast(str, url)
            status = cast(int, status)
            headers = cast(dict, headers)
            content = cast(str, content)

            # This doesn't work in versions prior to 3.10
            match status:
                # Is a valid URL
                case 200 | 301 | 302 | 401 | 403:
                    du: DiscoveredURL = DiscoveredURL(url, status, headers, content)
                    discovered_urls.append(du)
                    msg: str = f"Found: HTTP {status}: {url}"
                    logger.debug(msg)
                    #info(msg)
                # URL not found
                case 404:
                    # Test 404
                    # It's treated as 200 when it's a false positive
                    fhash: str = ssdeep.hash(f"{status}{content}")
                    if not is_error_page(err_data, fhash):
                        status = 200 # fix status code
                        du: DiscoveredURL = DiscoveredURL(
                                url,
                                status,
                                headers,
                                content
                            )
                        discovered_urls.append(du)
                        msg: str = f"Found: HTTP {status}: {url}"
                        logger.debug(msg)
                        #info(msg)
                    # URL not found
                    else:
                        msg: str = f"HTTP 404: {url}"
                        logger.error(msg)
                        error(msg, terminate=False)

                # Server error
                case _ if 500 <= status < 600:
                    msg: str = f"HTTP 500: {url}"
                    logger.error(msg)
                    error(msg, terminate=False)
                # Another status code maybe?
                case _:
                    msg: str = f"HTTP {status}: {url}"
                    logger.error(msg)
                    error(msg, terminate=False)

    return discovered_urls

def main() -> None:
    global MANUALLY_ABORTED

    # CLI arguments
    ap = ArgumentParser(
            add_help=True,
            description="Módulo 5 - Proyecto final" \
                "Etapa 1: Reconocimiento Automatizado de Superficie de Ataque"
        )
    ap.add_argument(
            "-u",
            "--url",
            action="store",
            dest="url",
            help="Url a analizar",
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
            "-w",
            "--worlist",
            action="store",
            dest="wordlist",
            help="Diccionario para realizar las pruebas de directorios ocultos.",
            required=True
        )
    ap.add_argument(
            "--workers",
            action="store",
            dest="workers",
            help="Workers en el thread pool.",
            default=1
        )
    args = ap.parse_args()

    # Validates url
    url: Union[ParseResult, ParseResultBytes] = urlparse(args.url)
    if not all([url.scheme, url.netloc]):
        logger.error(f"The given URL is invalid: '{args.url}'");
        error("The URL is invalid!")

    # Set base url
    base_url: str = f"{url.scheme}://{url.netloc}/"
    info(f"Base URL: {base_url}")
    logger.debug(f"Base URL: {base_url}")

    # Validate workers
    workers: int = 1
    try:
        workers = int(args.workers)
        if workers < 1:
            raise ValueError()
    except ValueError:
        error(f"--workers debe ser un entero mayor 0")

    # Validates wordlist
    if not exists(args.wordlist):
        error(f"Wordlist not found at: {args.wordlist}")

    # Reads wordlist
    wl: List = read_file(args.wordlist).split("\n") # type: ignore
    err_data: List[str] = detect_error_page(base_url)

    # The reconnaissance process was manually aborted by the user
    if MANUALLY_ABORTED:
        return

    urls: List[DiscoveredURL] = discover_urls(base_url, iter(wl), args.timeout,
        err_data, workers)
    info(f"{len(urls)} URLs found!")

    # The reconnaissance process was manually aborted by the user
    if MANUALLY_ABORTED:
        return

    # Nothing found
    if not urls:
        info("No URLs was discovered!")

    # Analizes the forms
    URLs: List[Dict] = [] # Stores the final output log data
    for du in urls:
        info(f"URL: {du.url}")
        headers: Dict = analize_headers(du.headers) # type: ignore
        forms: Dict = analize_forms(du.content) # type: ignore

        if headers or forms:
            item: Dict = {"url": du.url}
            item["headers"] = headers if headers else {}
            item["forms"] = forms if forms else {}
            URLs.append(item)

    # Saves the results into DATE_TIME_log.json
    outfile: str = f"{LOG_DIR}{NOW}_{url.netloc}_log.json"
    logger.debug(f"Saving results into: {outfile}")
    if URLs:
        with open(outfile, "w") as f:
            dump(URLs, f, indent=4)
            info(f"Results saved at: {outfile}")
    # No results were found
    else:
        info("No results were found!")

# Entry point
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Abborted!")
        error("Abborted!")
