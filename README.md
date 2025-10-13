# VIPER 1.2

VIPER is a Python-based command-line tool for fast domain discovery, designed for attack surface mapping and threat intelligence gathering. It leverages search engines to find domains related to specific keywords and provides advanced filtering and analysis capabilities.

<img width="671" height="279" alt="Screenshot 2025-10-13 at 15 35 04" src="https://github.com/user-attachments/assets/2d6bf05f-b167-4d11-b354-080e378b0357" />

## Key Features

  * **Keyword-based Domain Discovery**: Searches public sources like DuckDuckGo and Bing to find domains based on one or more keywords.
  * **Multi-threaded Directory Filtering**: Concurrently checks for the existence of a specific directory or file (e.g., `/admin`, `/wp-login.php`) on found domains.
  * **Web Technology Detection**: Identifies web technologies used by targets, including CMS (WordPress, Joomla), frameworks (React, Angular), and analytics tools.
  * **Multiple Output Formats**: Exports results in `TXT`, `JSON`, `CSV`, and a user-friendly `HTML` report format.
  * **Anti-Detection Mechanisms**: Utilizes User-Agent rotation and randomized delays between requests to avoid blocks and simulate human behavior.
  * **Self-Update Capability**: Includes a function to check for and install the latest version of the tool directly from its GitHub repository.
  * **External Configuration**: Key settings like user agents, blacklisted domains, and search engine parameters can be modified via the `config/config.json` file without altering the source code.

## Important Notes

**Search Engine Limitations**: Modern search engines implement aggressive anti-bot protection. VIPER uses advanced Google Dorking techniques and multiple fallback sources (Bing, DuckDuckGo, Brave, Common Crawl) to maximize results. However, you may experience:

* Limited results due to rate limiting
* Temporary blocks after multiple searches
* Better results when using moderate delays (--delay-min 3 --delay-max 8)
* Improved success rates when using VPN/proxy or different networks

**Best Practices**:
* Use realistic delays between requests
* Avoid running multiple instances simultaneously
* Consider breaking large keyword lists into smaller batches
* Wait 10-15 minutes between intensive scans from the same IP

## Installation

VIPER is built for Python 3 and has a few dependencies.

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/byfranke/viper.git
    cd viper
    ```

2.  **Install dependencies:**
    [cite\_start]The project includes a `requirements.txt` file that lists all necessary libraries[cite: 1]. Install them using pip.

    ```bash
    python3 -m pip install -r requirements.txt
    ```

3.  **(Optional) Make the script executable:**

    ```bash
    chmod +x viper.py
    ```

## Usage

The tool is operated from the command line, taking keywords as direct input or from a file, along with options to customize the scan.

**Basic Syntax:**

```bash
./viper.py [keywords...] [options]
```

### Main Arguments

| Argument | Alias | Description |
| --- | --- | --- |
| `keywords` | | Keywords for the domain search (e.g., "wordpress" "cms sites"). |
| `--list` | `-l` | Path to a file containing a list of keywords (one per line). |
| `--output` | `-o` | Output file to save results. If not specified, prints to STDOUT. |
| `--limit` | | Maximum number of domains to find (default: 50). |
| `--dir` | `-d` | Filter domains that have a specific directory or page. |
| `--detect-tech`| | Enable detection of web technologies (CMS, frameworks, etc.). |
| `--format` | `-f` | Output format: `txt`, `json`, `csv`, or `html` (default: txt). |
| `--threads` | `-t` | Number of threads for directory checking (default: 5). |
| `--verbose` | `-v` | Enable verbose mode for detailed debug information. |
| `--update` | | Check for and install updates from GitHub. |
| `--version` | | Display the current tool version. |

## Examples

**Basic Search**

```bash
./viper.py --list keywords.txt --limit 100 --output domains.txt
```

**Directory Filtering**
Find WordPress sites and check for the existence of `/wp-admin`.

```bash
./viper.py "wordpress" --dir /wp-admin --output wp-sites.txt
```

**Technology Detection**
Find e-commerce sites, detect their technologies, and save the results as a JSON file.

```bash
./viper.py "e-commerce" --detect-tech --format json -o results.json
```

**Advanced Options**
Use 10 threads for directory checks with custom delays between requests.

```bash
./viper.py "security" --threads 10 --delay-min 1 --delay-max 3
```

## Output Formats

  * **txt**: A simple plain text list of domains or URLs (default format).
  * **json**: Structured JSON output containing scan metadata and detailed information for each domain.
  * **csv**: A comma-separated values file suitable for import into spreadsheets, including details like status codes and detected technologies.
  * **html**: A self-contained, visually organized HTML report of the scan results.

## Configuration

VIPER's behavior can be customized by editing the `config/config.json` file. This allows you to:

  * Modify the list of `blacklisted_domains` to be ignored during scans.
  * Add or change the `user_agents` for making web requests.
  * Adjust the `search_engines` URLs and result selectors.


---


## Donation Support

This tool is maintained through community support. Help keep it active:

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)
