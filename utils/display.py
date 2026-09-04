import os
import sys

# Force UTF-8 output on Windows to avoid cp1254 encoding errors
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

class Colors:
    """ANSI color codes for terminal output formatting."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the colored ASCII art banner for e'tscanner."""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
       ' _                                     
      / / |_                                   
  ___/ /| __|___  ___ __ _ _ __  _ __   ___ _ __ 
 / _ \\/ | |_/ __|/ __/ _` | '_ \\| '_ \\ / _ \\ '__|
|  __/  | |_\\__ \\ (_| (_| | | | | | | |  __/ |   
 \\___|   \\__|___/\\___\\__,_|_| |_|_| |_|\\___|_|   
                                                 
{Colors.MAGENTA}  e'tscanner - Asynchronous TCP Port Scanner
{Colors.RESET}"""
    print(banner)

def print_info(message: str):
    """Print an informational message."""
    print(f"{Colors.BLUE}[*]{Colors.RESET} {message}")

def print_success(message: str):
    """Print a success message."""
    print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")

def print_warning(message: str):
    """Print a warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")

def print_error(message: str):
    """Print an error message."""
    print(f"{Colors.RED}[-]{Colors.RESET} {message}")

def print_port_result(port: int, service: str = ""):
    """Print an open port and its service gracefully."""
    service_text = f" ({service})" if service else ""
    print(f"    {Colors.GREEN}→ Port {port} is open{Colors.RESET}{Colors.CYAN}{service_text}{Colors.RESET}")
