# pip install requests
# pip install colorama
import sys
import requests
import subprocess
import json
import csv

def getRepoLinks(user):
  data = requests.get(url = 'https://api.github.com/users/' + user + '/repos').json()
  repos = []
  for item in data:
    repos.append([item['name'], item['html_url'], item['html_url'] + '/archive/master.zip'])
  return repos

def scan(url):
  result = subprocess.check_output(['python3', 'VxApi/vxapi.py', 'scan_url_to_file', url, 'all'])
  data = json.loads(result.decode('ascii'))
  haLink = 'https://hybrid-analysis.com/sample/' + data['sha256']
  vtResult = 'No'
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
    for repo in repos:
      halink, vtresult = scan(repo[2])
      rows.append([str(count),repo[0],repo[1],repo[2],halink,'',vtresult])
      count += 1
    with open(username+'.csv', 'w') as csvFile:
      writer = csv.writer(csvFile)
      writer.writerows(rows)
    csvFile.close()
  else:
    print("Please input a valid Github username after the program name to run the scrapper")


if __name__ == "__main__":
  main()