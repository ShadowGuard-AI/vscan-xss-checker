import argparse
import requests
from bs4 import BeautifulSoup
import logging
import urllib.parse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Every request this tool sends carries this timeout, in seconds.
REQUEST_TIMEOUT = 10

# XSS Payloads (extend as needed)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "';alert('XSS');//"
]

def setup_argparse():
    """Sets up the argument parser for the command-line interface."""
    parser = argparse.ArgumentParser(description="vscan-xss-checker: Detects potential XSS vulnerabilities.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-p", "--payloads", nargs='+', help="Custom XSS payloads to use (optional).", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debugging).")
    return parser.parse_args()

def _is_reflection(payload, response_text, baseline_text):
    """
    A finding needs the payload itself reflected, and the reflection
    must be new: a payload string that already appears in the baseline
    response (fetched without the payload) is page content, not a
    reflection. The mere presence of a script, img, or svg tag in a
    page is never a finding.
    """
    return payload in response_text and payload not in baseline_text

def inject_payloads(url, payloads):
    """
    Injects XSS payloads into form fields and URL parameters.

    Args:
        url (str): The URL to scan.
        payloads (list): A list of XSS payloads to inject.

    Returns:
        (list, int): A list of vulnerable URLs (if any are found), and
        the number of requests that received a response, so the caller
        can tell a completed scan from one that reached nothing.
    """
    vulnerable_urls = []
    succeeded = 0
    try:
        # Check URL parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if query_params:
            # Baseline: the same URL with its original parameter values.
            baseline_text = ""
            try:
                baseline = requests.get(url, timeout=REQUEST_TIMEOUT)
                baseline.raise_for_status()
                succeeded += 1
                baseline_text = baseline.text
            except requests.exceptions.RequestException as e:
                logging.error(f"Error during baseline request for {url}: {e}")

            for param in query_params:
                for payload in payloads:
                    # Create a new URL with the injected payload
                    new_query_params = query_params.copy()
                    new_query_params[param] = [payload] # Replace with the payload
                    new_query = urllib.parse.urlencode(new_query_params, doseq=True)  # Encode back to string, doseq=True handles multiple values for a single key

                    new_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))


                    try:
                        response = requests.get(new_url, timeout=REQUEST_TIMEOUT)
                        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
                        succeeded += 1

                        if _is_reflection(payload, response.text, baseline_text):
                            logging.warning(f"Potential XSS vulnerability found in URL parameter '{param}': {new_url}")
                            vulnerable_urls.append(new_url)

                    except requests.exceptions.RequestException as e:
                        logging.error(f"Error during request for URL parameter '{param}': {e}")


        # Check form fields
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()  # Raise HTTPError for bad responses
            succeeded += 1

            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                # Resolve the action against the page URL. A relative
                # action such as /submit, or an empty or missing one,
                # becomes a full URL for the page's own origin.
                action_attr = form.get('action')
                action = urllib.parse.urljoin(url, action_attr) if action_attr else url
                method = form.get('method', 'GET').upper()

                inputs = form.find_all('input')
                data = {}

                for input_field in inputs:
                    name = input_field.get('name')
                    if name:  # Only process fields with a name
                        data[name] = ""  # Set default to empty string

                if not data:
                    continue

                # Baseline for this form: the same submission with the
                # fields left empty, so static page content is known.
                baseline_text = ""
                try:
                    if method == 'GET':
                        baseline_url = _build_get_url(action, data)
                        baseline = requests.get(baseline_url, timeout=REQUEST_TIMEOUT)
                    else:
                        baseline = requests.post(action, data=data, timeout=REQUEST_TIMEOUT)
                    baseline.raise_for_status()
                    succeeded += 1
                    baseline_text = baseline.text
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error during baseline request for form at {action}: {e}")

                # Inject payloads into the form data
                for payload in payloads:
                    for field in data:
                        data[field] = payload  # Inject the payload into each field, one by one

                        try:
                            if method == 'GET':
                                full_url = _build_get_url(action, data)
                                response = requests.get(full_url, timeout=REQUEST_TIMEOUT)
                                response.raise_for_status()  # Raise HTTPError for bad responses
                                succeeded += 1

                                if _is_reflection(payload, response.text, baseline_text):
                                    logging.warning(f"Potential XSS vulnerability found in form (GET, field '{field}'): {full_url}")
                                    vulnerable_urls.append(full_url)
                            elif method == 'POST':
                                response = requests.post(action, data=data, timeout=REQUEST_TIMEOUT)
                                response.raise_for_status()  # Raise HTTPError for bad responses
                                succeeded += 1
                                if _is_reflection(payload, response.text, baseline_text):
                                    logging.warning(f"Potential XSS vulnerability found in form (POST, field '{field}'): {action}")
                                    vulnerable_urls.append(action)
                        except requests.exceptions.RequestException as e:
                            logging.error(f"Error during request for form (field '{field}'): {e}")
                        data[field] = ""  # Reset the field to an empty string for the next iteration
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching or parsing the initial page: {e}")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

    return vulnerable_urls, succeeded


def _build_get_url(action, data):
    """
    Build a GET submission URL for a form: the form data is merged
    with any query string the action already carries, with proper
    query encoding, instead of being concatenated onto the action.
    """
    parsed = urllib.parse.urlparse(action)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query.update(data)
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))


def main():
    """Main function to execute the XSS checker."""
    args = setup_argparse()

    if not args.url:
        logging.error("URL is required.")
        sys.exit(1)

    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        logging.error("URL must start with http:// or https://")
        sys.exit(1)

    payloads_to_use = args.payloads if args.payloads else XSS_PAYLOADS

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Set logging to DEBUG for verbose output
        logging.debug(f"Scanning URL: {args.url}")
        logging.debug(f"Using payloads: {payloads_to_use}")

    vulnerable_urls, succeeded = inject_payloads(args.url, payloads_to_use)

    if succeeded == 0:
        print("\nScan failed: the target could not be reached, so no verdict was reached.")
        sys.exit(1)

    if vulnerable_urls:
        print("\nVulnerabilities Found:")
        for url in vulnerable_urls:
            print(f"- {url}")
    else:
        print("\nNo vulnerabilities found.")


if __name__ == "__main__":
    main()
