# Security-Project-Tools
Tools for the final project of EECS 349

# Dependencies
- pip install requests
- pip install colorama
- pip install tqdm

# How to run
python3 scrape-n-scan.py username
- exports a username.csv with the results and a second file username_following.csv with the users they are following

python3 scrape-n-scan.py username #
- exports a bunch of csv files of data for the first user and crawls to a depth of # for their following users repos