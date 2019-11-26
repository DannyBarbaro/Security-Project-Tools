# pip install requests
# pip install colorama 
# pip install tqdm
import sys
import requests
import subprocess
import json
import csv
from tqdm import tqdm

# Writes the csv for a user and returns a list of the people that they are following
def scanUser(username): 
  print(username)
  rows = [['Project ID','Project Name','Project Link','Zip Link','HA Link','HA Detection Result','VT flagged']]
  count = 1
  repos = getRepoLinks(username)
    
  # Provide a visual indicator of scanning progress on the command line
  for repo in tqdm(repos):
    halink, vtresult = scan(repo[2])
    rows.append([str(count),repo[0],repo[1],repo[2],halink,'',vtresult])
    count += 1

  # Write HA scans to CSV file in root folder
  writeToCSV(username+'.csv', rows)

  #Get list of people Malicious users are following
  return getFollowing(username)

def getRepoLinks(user):
  data = requests.get(url = 'https://api.github.com/users/' + user + '/repos?per_page=100').json()
  repos = []
  for item in data:
    repos.append([item['name'], item['html_url'], item['html_url'] + '/archive/master.zip'])
  return repos

def scan(url):
  result = subprocess.check_output(['python3', 'VxApi/vxapi.py', 'scan_url_to_file', url, 'all'])
  data = json.loads(result.decode('ascii'))
  haLink = 'https://hybrid-analysis.com/sample/'
  vtResult = 'No'
  if 'sha256' in data:
    haLink += data['sha256']
  if 'scanners' in data:
    for test in data['scanners']:
      if test['name'] == 'VirusTotal' and test['status'] == 'malicious':
        vtResult = 'Yes'
  return haLink, vtResult

def getFollowing(user):
  whoUserFollows = requests.get(url = 'https://api.github.com/users/' + user + '/following').json()
  followsList = []
  for person in whoUserFollows:
    followsList.append(person['login'])
  return followsList

def makeFollowingCSV(username, following):
  rows = [['ID', 'Username', 'Profile Link']]
  count = 1
  for user in tqdm(following):
    rows.append([str(count),user,'https://github.com/'+user])
    count += 1
  writeToCSV(username+'_following.csv', rows)

def writeToCSV(name, rows):
  with open(name, 'w') as csvFile:
    writer = csv.writer(csvFile)
    writer.writerows(rows)
  csvFile.close()

def runCrawl(username, depth):
  if depth > 0:
    following = scanUser(username)
    makeFollowingCSV(username, following)
    print('Number users following: ' +  str(len(following)))
    for user in following:
      runCrawl(user, depth-1)

def main():
  # Run one layer deep and return list of following
  if len(sys.argv) == 2:
    username = sys.argv[1]
    # scan top 100 repos and get their followers
    following = scanUser(username)
    makeFollowingCSV(username, following)
  # Run the defined number of layers deep and build all of the csv files
  if len(sys.argv) == 3:
    username = sys.argv[1]
    depth = int(sys.argv[2])
    runCrawl(username, depth)
  else:
    print("Please input a valid Github username after the program name to run the scrapper")


if __name__ == "__main__":
  main()