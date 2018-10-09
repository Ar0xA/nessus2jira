import argparse
from bs4 import BeautifulSoup
from jira import JIRA
from collections import Counter
from objdict import ObjDict
from dateutil.parser import parse
from datetime import timedelta
import time
import sys
import hashlib

#jira = JIRA('http://10.1.2.36:8080',basic_auth=('test',''))

#issue = jira.issue('TES-1')
#print (issue)
#jira.add_comment(issue, 'test')

#create issue
#issue_dict = {
#    'project': {'key': 'TES'},
#    'summary': 'test issue',
#    'description': 'test issue desc',
#    'issuetype': {'name': 'Task'}
#}
#new_issue = jira.create_issue(fields = issue_dict)
#print (new_issue)
#
#

def auth_to_jira(args):
    try:
        jira = JIRA(args.jiraserver + ':' + str(args.jiraport), basic_auth =('test','allemaal'))
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        print (message)
        return None
    return jira

def send_to_jira(json_data, args):
    #ok so first we auth to jira
    print (json_data)
    jira = auth_to_jira(args)
    if jira:
        print ("Valid Jira session") 
        #now we look for if the item already exists
        # we do this by finding if its a compliance item or not
        # due to different fields
#        print (json_data.compliance)
        hash_data = ""
        if json_data.compliance:
            #we create the unique value from
            #taskid, hostname and compliancecheckname
            hash_data = json_data.taskid + json_data.hostname + json_data.compliancecheckname
        else:
            #its not a compliance item, so now we use other data for the hash
            hash_data = json_data.taskid + json_data.hostname + json_data.pluginid + json_data.pluginname
#        print (hash_data)
        if len(hash_data) > 1:
            hashval = hashlib.sha512(str(hash_data).encode('utf-8')).hexdigest()
        else:
            print("issue creating valid hash value, panic")
            sys.exit(1)
#        print (hashval)
        #ok so this hashval, lets see if we can find it already
        #the hash value will go into the field of args.jirahashvalue
        #project key will be stored in args.jiraprojectkey
        print ("Searching if hashvalue exists")
        searchStr = "project=" + args.jiraprojectkey + " and " +args.jirahashvalue + "~" +hashval
        jiratickets= jira.search_issues(searchStr)
        if len(jiratickets) == 0:
            print ("Hash not found, lets create ticket")
            #first lets figure out the issue type
            #and fill the data as it should
            issue_dict ={}
            scanTime = json_data.hostscanend.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
            print (scanTime)
            if json_data.compliance:
                print ("Issue type: compliance")
                issue_dict = {
                    'project': {'key': args.jiraprojectkey},
                    'issuetype': {'name': 'Compliance'},
                    'summary': json_data.compliancecheckname,
                    'description': json_data.description,
                    'customfield_10107': hashval,
                    'customfield_10108': scanTime,
                    'customfield_10109': json_data.hostname
		}
                print (issue_dict)
                new_issue = jira.create_issue(fields = issue_dict)
                print (new_issue)
            else:
                print ("Issue type: vulnerability")
        else:
            print ("hash value found, we need to check comments and probably update those")
            #ok so we get all comments, and see if theres one with the current scanTime
            print ("Found hash in %s, getting comments" % (jiratickets[0]))
            issue = jira.issue(jiratickets[0])
            print(issue.raw['fields'])
#            print (issue.fields.customfield_10109)
            comments= jira.comments(issue)
            print (comments)
            #if no comments, check scandate wtih current scandate
            
    #if it exists, we check the date of the last update and the date of the scan
    #if the scan data is newer than the last update -> add comment
    #else give error

    #if the item isnt found, create a new ticket.
    sys.exit(1)


def parse_to_json(nessus_xml_data, args):

    #some quick report checking
    data =ObjDict()

    tmp_scanname = nessus_xml_data.report['name']
    if len(tmp_scanname) == 0:
        print ('Didn\'t find report name in file. is this a valid nessus file?')
        sys.exit(1)
    else:
        data.scanname = tmp_scanname

    #policyused
    data.scanpolicy = nessus_xml_data.policyname.get_text()

    # see if there are any hosts that are reported on
    hosts = nessus_xml_data.findAll('reporthost')
    if len(hosts) == 0:
        print ('Didn\'t find any hosts in file. Is this a valid nessus file?')
        sys.exit(1)
    else:
        print ('Found %i hosts' % (len(hosts)))

    #find the Task ID for uniqueness checking
    #test: is this unique per RUN..or per task?
    task_id = ""
    tmp_prefs = nessus_xml_data.findAll('preference')
    for pref in tmp_prefs:
        if "report_task_id" in str(pref):
            task_id = pref.value.get_text()
#    print (task_id)

    print ("Checking for results and creating tickets. This might take a while...")
    for host in hosts:
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            host_info = ObjDict()
            #host_info.reportfindings = []
            #lets get the host information
            host_info.taskid= task_id

            host_info.hostname = host['name']


            host_info.hostip = host.find('tag', attrs={'name': 'host-ip'}).get_text()
            macaddress = host.find('tag', attrs={'name': 'mac-address'})
            if macaddress:
                host_info.hostmacaddress = macaddress.get_text()
            else:
                host_info.hostmacaddress = None

            credscan = host.find('tag', attrs={'name': 'Credentialed_Scan'})
            if credscan:
                 host_info.credentialedscan = credscan.get_text()
            else:
                host_info.credentialedscan = None

            host_info.hostscanstart = host.find('tag', attrs={'name': 'HOST_START'}).get_text()
            #convert to normal date format
            host_info.hostscanstart = parse(host_info.hostscanstart)
            #convert to UTC time
            timeoffset = int((time.localtime().tm_gmtoff)/3600)
            host_info.hostscanstart =host_info.hostscanstart - timedelta(hours=timeoffset)

            host_info.hostscanend = host.find('tag', attrs={'name': 'HOST_END'}).get_text()
            host_info.hostscanend = parse(host_info.hostscanend)
            host_info.hostscanend =  host_info.hostscanend - timedelta(hours=timeoffset)
            #host_info["@timestamp"] = host_info.hostscanend

            #fqdn might be optional
            host_fqdn = host.find('tag', attrs={'name': 'host-fqdn'})
            if host_fqdn:
                host_info.hostfqdn = host_fqdn.get_text()
            else:
                host_info.hostfqdn = None

            #get all report findings info
            try:
                #these fields should always be present
                host_info.severity = rItem['severity']
                host_info.port = rItem['port']
                host_info.svc_name = rItem['svc_name']
                host_info.protocol = rItem['protocol']
                host_info.pluginid = rItem['pluginid']
                host_info.pluginname = rItem['pluginname']
                host_info.plugintype = rItem.find('plugin_type').get_text()
                host_info.pluginfamily = rItem['pluginfamily']
                host_info.riskfactor = rItem.find('risk_factor').get_text()
                agent = rItem.find('agent')

                if agent:
                    host_info.agent = agent.get_text()
                else:
                    host_info.agent = None

                compliance_item = rItem.find('compliance')
                if compliance_item:
                    host_info.compliance = True
                else:
                    host_info.compliance = False

                #this stuff only around when its a compliance scan anyway
                host_info.compliancecheckname = None
                host_info.complianceauditfile = None
                host_info.complianceinfo = None
                host_info.complianceresult = None
                #host_info.compliancereference = None
                host_info.complianceseealso = None


                comaudit = rItem.find('cm:compliance-audit-file')
                if comaudit:
                    host_info.complianceauditfile =  comaudit.get_text()
                else:
                   host_info.complianceauditfile = None

                comcheck = rItem.find('cm:compliance-check-name')
                if comcheck:
                    host_info.compliancecheckname =  comcheck.get_text()
                else:
                   host_info.compliancecheckname = None

                cominfo = rItem.find('cm:compliance-info')
                if cominfo:
                    host_info.complianceinfo =  cominfo.get_text()
                else:
                   host_info.complianceinfo = None

                comsee = rItem.find('cm:compliance-see-also')
                if comsee:
                    host_info.complianceseealso =  comsee.get_text()
                else:
                   host_info.complianceseealso = None

                comref = rItem.find('cm:compliance-reference')
                #host_info.compliancereference['LEVEL']= ObjDict()

                if comref:
                    host_info.compliancereference = ObjDict()

                    compliancereference =  comref.get_text().split(",")
                    for ref in compliancereference:
                        comprefsplit = ref.split("|")
                        host_info.compliancereference[comprefsplit[0]] = ObjDict()
                        host_info.compliancereference[comprefsplit[0]] =comprefsplit[1]
                else:
                   host_info.compliancereference = None

                comres = rItem.find('cm:compliance-result')
                if comres:
                    host_info.complianceresult =  comres.get_text()
                else:
                   host_info.complianceresult = None

                descrip = rItem.find('description')
                if descrip:
                    host_info.description = descrip.get_text()
                else:
                    host_info.description = None

                synop = rItem.find('synopsis')
                if synop:
                    host_info.synopsis = synop.get_text()
                else:
                    host_info.synopsis = None

                solut = rItem.find('solution')
                if solut:
                    host_info.solution = solut.get_text()
                else:
                    host_info.solution = None

                plugin_output = rItem.find('plugin_output')
                if plugin_output:
                    host_info.pluginoutput = plugin_output.get_text()
                else:
                    host_info.pluginoutput = None

                expl_avail = rItem.find('exploit_available')
                if expl_avail:
                    host_info.exploitavailable = expl_avail.get_text()
                else:
                    host_info.exploitavailable = None

                expl_ease = rItem.find('exploitability_ease')
                if expl_ease:
                      host_info.exploitabilityease = expl_ease.get_text()
                else:
                      host_info.exploitabilityease = None

                cvss = rItem.find('cvss_base_score')
                if cvss:
                    host_info.cvssbasescore = cvss.get_text()
                else:
                    host_info.cvssbasescore = None

                cvss3 = rItem.find('cvss3_base_score')
                if cvss3:
                    host_info.cvss3basescore = cvss3.get_text()
                else:
                    host_info.cvss3basescore = None

                ppdate = rItem.find('patch_publication_date')
                if ppdate:
                    host_info.patchpublicationdate = parse(ppdate.get_text())
                else:
                    host_info.patchpublicationdate = None

                #these items can be none, one or many if found
                host_info.cve = []
                host_info.osvdb = []
                host_info.rhsa = []
                host_info.xref = []

                allcve = rItem.findAll('cve')
                if allcve:
                    for cve in allcve:
                        host_info.cve.append(cve.get_text())

                allosvdb = rItem.findAll('osvdb')
                if allosvdb:
                    for osvdb in allosvdb:
                        host_info.osvdb.append(osvdb.get_text())


                allrhsa = rItem.findAll('rhsa')
                if allrhsa:
                    for rhsa in allrhsa:
                        host_info.rhsa.append(rhsa.get_text())

                allxref = rItem.findAll('xref')
                if allxref:
                    for xref in allxref:
                        host_info.xref.append(xref.get_text())

                #we have all data in host_info, why not send that instead?
                #print ("Finding for %s complete, sending to ES" % (host_info.hostname))
#                json_data = host_info.dumps()
                #print (json_data)
                if not args.fake:
                    #ok first order of business, is the severity over the minimum treshhold or higher?
                    #SEVERITY 0 = INFO, 1 =  LOW, 2 = MEDIUM, 3= HIGH, 4 = CRITICAL
                    severityMap = {'INFO':'0', 'LOW': '0', 'MEDIUM': '2', 'HIGH':'3', 'CRITICAL': '4' }
                    if int(host_info.severity) >= int(severityMap[args.level]):
                        print("Severity is a match or higher, Viable item!")
                        send_to_jira(host_info, args)
                    else:
                        print("Severity %s is lower than treshhold, no jira ticket" % host_info.severity)
            except Exception as e:
                print ("Error:")
                print (e)
                print (rItem)
                sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description = 'Create tickets for jira from a .nessus result file.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input', help = 'Input file in .nessus format',
        default = None)
    parser.add_argument('-js', '--jiraserver', help = 'jira server',
        default = 'http://127.0.0.1')
    parser.add_argument('-jp', '--jiraport', help = 'elasticsearch port',
        default = 8080)
    parser.add_argument('-jpk','--jiraprojectkey', help='Name of the project key',
        default = 'TES')
#    parser.add_argument('-jit','--jiraissuetype', help='Issue type of the ticket',
#        default = 'Vulnerability')
    parser.add_argument('-jhv', '--jirahashvalue', help ='Hash value of finding', default= 'HashValue')
    parser.add_argument('-t', '--type', help = 'What type of result to parse the file for.', choices = ['both', 'vulnerability','compliance' ],
        default = 'both')
    parser.add_argument('-l', '--level', help='from what level do we want to create tickets', choices =['INFO','LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default = 'HIGH')
    parser.add_argument('-f','--fake', help = 'Do everything but actually send data to jira', action = 'store_true')
    #group.add_argument('-c', '--config', help = 'Config file for script to read settings from. Overwrites all other cli parameters', default = None)
    args = parser.parse_args()
    return args

def main():
    args = parse_args()

    #ok, if not
    if (not args.input) and (not args.nessusscanname):
        print('Need input file to export. Specify one in the configuation file,  with -i (file) or -rn (reportname)\n See -h for more info')
        sys.exit(1)

    if args.input:
        nessus_scan_file = args.input
    else:
        nessus_scan_file = args.nessustmp + "/" + args.nessusscanname
    print ("Nessus file to parse is %s" % (nessus_scan_file))

    # read the file..might be big though...
    with open(nessus_scan_file, 'r') as f:
        print ('Parsing file %s as xml into memory, hold on...' % (args.input))
        nessus_xml_data = BeautifulSoup(f.read(), 'lxml')

    parse_to_json(nessus_xml_data, args)
    #print ('parse to json')

if __name__ == "__main__":
  main()
print ("Done.")
