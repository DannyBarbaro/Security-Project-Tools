# pip install requests
# pip install colorama 
# pip install tqdm
import sys
import requests
import subprocess
import json
import csv
from tqdm import tqdm

def getFollowing(user):
  whoUserFollows = requests.get(url = 'https://api.github.com/users/' + user + '/following').json()
  followsList = []
  for person in whoUserFollows:
    followsList.append([person['login'], person['url']])
  return followsList

def getRepoLinks(user):
  data = requests.get(url = 'https://api.github.com/users/' + user + '/repos?per_page=100').json()
  print(len(data))
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

def main():
  if len(sys.argv) > 1:
    username = sys.argv[1]
    rows = [['Project ID','Project Name','Project Link','Zip Link','HA Link','HA Detection Result','VT flagged']]
    count = 1
    repos = getRepoLinks(username)
    
    # Provide a visual indicator of scanning progress on the command line
    for repo in tqdm(repos):
      halink, vtresult = scan(repo[2])
      rows.append([str(count),repo[0],repo[1],repo[2],halink,'',vtresult])
      count += 1

    # Write HA scans to CSV file in root folder
    with open(username+'.csv', 'w') as csvFile:
      writer = csv.writer(csvFile)
      writer.writerows(rows)
    csvFile.close()

    #Get list of people Malicious users are following
    following = getFollowing(username)
    rows2 = [['Username', 'Profile Link']]
    count2 = 1
    for user in following:
      rows2.append([str(count2),user[0],user[1]])
      count2 += 1
    with open(username+'FollowingList.csv', 'w') as csvFile:
      writer = csv.writer(csvFile)
      writer.writerows(rows2)
    csvFile.close()

  else:
    print("Please input a valid Github username after the program name to run the scrapper")


if __name__ == "__main__":
  main()