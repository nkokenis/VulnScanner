# External dependencies
import sys
import socket
from datetime import datetime

# Constant:
# Max Timeout
#
# Description:
# The maximum amount of time, in seconds, to try and scan a host before giving up. This value can be set by the user
# upon execution if desired.
MAX_TIMEOUT = 20

# Constant
# Max Retries
#
# Description:
# The maximum number of retries to connect to a host before giving up. This value can be set by the user upon
# execution if desired.
MAX_RETRIES = 1

# Function:
# Input Handler
#
# Description:
# This function is responsible for handling user input to the program. The program accepts the following command line.
# arguments:
#   -p <port number, range, or comma separated list> (required argument)
#   -pA (scans all ports)
#   -v (prints more verbose output, similar to nmap)
#   -h (prints the help menu, explaining program usage and command line arguments in detail)
#   --max-retries <maximum number of retries before giving up>
#   --host-timeout <maximum amount of time before giving up, in seconds>
def input_handler():
    if len(sys.argv) == 2 and sys.argv[1] == '-h':
        print(
            "The program accepts the following command line arguments (please note that the -p argument is required for the program to run):\n"
            "-p <port number>\n"
            "   Scan a single port by specifying only that number as the -p argument. Valid port numbers: 1-65535\n"
            "-p <port 1>,<port 2>,<port 3>\n"
            "   Scan a list of ports by separating them with commas (please dont use spaces between ports and commas). Valid port numbers: 1-65535\n"
            "-p <port 1>-<port 2>\n"
            "   Scan a range of ports by separating them with a hyphen (-). Valid port numbers: 1-65535\n"
            "-pA\n"
            "   Scan all ports and all protocols."
            "-v\n"
            "   Tells the program to print more verbose output, similar to Nmap. It will include open ports as they are found and estimated completion times.\n"
            "--max-retries <number>\n"
            "   The maximum number of retries for any given host before giving up. The default value is 1.\n"
            "--max-timeout <number>\n"
            "   The maximum amount of time, in seconds, to try and scan any given host before giving up. The default value is 20 seconds."
        )
        return
    if '-p' not in sys.argv and '-pA' not in sys.argv:
        print("Error: Port number or range missing.\nUsage: python.exe vscan.py -p <port number, range, or list>\nFor help: python.exe vscan.py -h")
        return
    else:
        # Valid input (still some handling to do here)
        print("Valid input")
    return

# Function:
# Main
#
# Description:
# Responsible for coordinating other functions and handling program output
def main() -> int:
    input_handler()
    return

if __name__ == "__main__":
    main()