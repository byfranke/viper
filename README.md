# VIPER - Threat Intelligence Tool

Fast domain discovery for attack surface mapping and threat hunting.

## Project Structure

```
viper/
├── config/
│   └── config.json        # Configuration file (blacklists, user agents, search engines)
├── modules/
│   ├── __init__.py       # Module initialization
│   ├── colors.py         # ANSI color definitions
│   └── utils.py          # Utility functions and classes
├── templates/
│   └── report.html       # HTML report template
├── viper.py             # Main script
└── requirements.txt     # Python dependencies
```

## Configuration

The project uses a configuration file (`config/config.json`) that contains:
- Blacklisted domains to exclude from results
- User agent strings for requests
- Search engine configurations

## Templates

The `templates` directory contains HTML templates used for report generation:
- `report.html`: Template for HTML report output

## Dependencies

Install required Python packages:

```bash
pip3 install -r requirements.txt
```

## Usage

Run VIPER with the following options:

```bash
python3 viper.py [options] <keywords>
```

For example:
```bash
python3 viper.py -l 100 -o results.txt -v "example.com"
```

## Options

- `-l, --limit`: Maximum number of domains to find (default: 50)
- `-o, --output`: Output file for results
- `-v, --verbose`: Enable verbose output
- `-f, --filter`: Directory/path to filter domains
- `-t, --threads`: Number of threads for parallel processing
- `-d, --tech`: Enable technology detection
- `--format`: Output format (txt, json, csv, html)
- `--update`: Update VIPER to the latest version