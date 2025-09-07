# Login Scanner

## Workflow:
Takes a xlsx input file with domain names in the first collumn of each row and scans them using HTTPX to find potential available login platforms
First performs a DNS Check, if valid it uses HTTPX with follow-redirect enabled to get to the final url
Finally it checks some commun paths which can be adjusted in the python code and checks the raw html content of the final webpage for keywords specified in the python code to find if the homepage has potentially a login platform

## Usage
login_scanner.py -i input.xlsx -o output.csv

