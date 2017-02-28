from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client
from pprint import pprint
from swiftclient.service import SwiftService
import keystoneauth1.exceptions
import getpass
from prettytable import PrettyTable

#Keystone Settings
auth_url = 'http://controller01:35357/v3'
domain_name = 'default'
#username = 'admin'
#password = ''
project_name = 'admin'

swift_options = {
    "auth_version": '3',
    "os_user_domain_name": domain_name,
    "os_project_name": project_name,
    "os_project_domain_name": domain_name,
    "os_auth_url": auth_url,
    #    "os_endpoint_type": 'admin'
}

#function to return report on swift accounts, quotas and usage
def projects_report(keystone, project=None):
    report = []
    if project:
        quotas = swift_get_quotas(project.name)
        report.append(dict(project = project.name,
                           description = project.description,
                           enabled = project.enabled,
                           quota = quotas['quota'],
                           quota_used = quotas['quota_used']))
    else:
        for project in keystone.projects.list():
            #do not collect data from cervice accounts
            if project.name in ['admin','service']:
                continue
            #copy swift options from template change project
            quotas = swift_get_quotas(project.name)
            #append to the report
            report.append(dict(project = project.name,
                               description = project.description[:27],
                               enabled = project.enabled,
                               quota = quotas['quota'],
                               quota_used = quotas['quota_used']))
    return report

def swift_get_quotas(project_name):
    sw_opt = swift_options
    sw_opt['os_project_name'] = project_name
    #collect stats() data from swift account
    with SwiftService(sw_opt) as swift:
        stats = swift.stat()
        #set quota to not defined if it is not set, ie unlimited
        try:
            quota = round(int(stats['headers']['x-account-meta-quota-bytes'])/1073741824, 0)
        except KeyError:
            quota = 'Not Defined'
        try:
            quota_used = round(int(stats['headers']['x-account-bytes-used'])/1073741824, 3)
        except KeyError:
            quota_used = 'N/A'
    return dict(quota = quota,quota_used = quota_used)
    

#function creates account(project), maps denovo-admins as ResellerAdmin
def project_create(keystone, project_name, description=None):
    #create project with given name
    domain = keystone.domains.find(name=domain_name)
    try:
        project = keystone.projects.create(project_name,domain,description=description)
    except keystoneauth1.exceptions.http.Conflict:
        print('Error. Dublicate Project name "{}".'.format(project_name))
        return None
        #project = keystone.projects.find(name=project_name)
    #grant denovo-admins group a 'ResellerAdmin role on the new project
    role_resellerAdmin = keystone.roles.find(name='ResellerAdmin')
    group_admins = keystone.groups.find(name='denovo-admins')
    admin_granted = keystone.roles.grant(role_resellerAdmin,group=group_admins,project=project)
    return project

def user_create(keystone, user_name, user_password, domain=domain_name, default_project=None, user_email=None):
    domain = keystone.domains.find(name=domain_name)
    try:
        user = keystone.users.create(user_name,domain=domain,
                                     default_project=default_project,
                                     password=user_password,
                                     email=user_email)
    except keystoneauth1.exceptions.http.Conflict:
        print('Error. Dublicate User name {}.'.format(user_name))
        return None
    return user

#grant new user a 'user' role on the new project
def user_role_add(keystone,user,project):
    role_user = keystone.roles.find(name='user')
    try:
        keystone.roles.grant(role_user,user=user,project=project)
    except:
        return False
    return True
                          
#update swift quota of the project
def swift_update_quota(project_name,new_quota_bytes):
    sw_opt = swift_options
    sw_opt['os_project_name'] = project_name
    with SwiftService(sw_opt) as swift:
        post = swift.post(options={'meta':['quota-bytes:{}'.format(new_quota_bytes)]})
    return post['success']

#connect to keystone
def keystone_connect(user,passwd):
    auth = v3.Password(auth_url=auth_url,
                       username=user,
                       password=passwd,
                       user_domain_name=domain_name,
                       project_name=project_name,
                       project_domain_name=domain_name)
    sess = session.Session(auth=auth)
    keystone = client.Client(session=sess)
    try:
        keystone.projects.list()
    except keystoneauth1.exceptions.http.Unauthorized:
        return None
    except keystoneauth1.exceptions.http.BadRequest:
        return None
    return keystone

#print swift quota/usage report
def print_report(report):
    table = PrettyTable(['Project','Description','Enabled','Qutoa, Gb','Used, Gb'])
    for line in report:
        table.add_row([line['project'],
                       line['description'],
                       line['enabled'],
                       line['quota'],
                       line['quota_used']])
    print(table)

#generate password
def generate_password(length):
    if not isinstance(length, int) or length < 8:
        raise ValueError("temp password must have positive length")
    from random import choice
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%^*(-_=+)'
    return ''.join([choice(chars) for i in range(length)])

#returns list of users wich have 'user' role in project
def get_project_users(keystone,project):
    users_list = []
    role_user = keystone.roles.find(name='user')
    for user in keystone.users.list():
        try:
            if keystone.roles.check(role_user,user=user,project=project):
                users_list.append(user)
        except keystoneauth1.exceptions.http.NotFound:
            continue
    return users_list

#returns list of projects wich user has a 'user' role in
def get_user_projects(keystone,user):
    projects_list = []
    role_user = keystone.roles.find(name='user')
    for project in keystone.projects.list():
        try:
            if keystone.roles.check(role_user,user=user,project=project):
                projects_list.append(project)
        except keystoneauth1.exceptions.http.NotFound:
            continue
    return projects_list

def menu():
    #authenticating with the keystone
    while True:
        username = input('Enter Your Username:\n')
        password = getpass.getpass('Password:\n')
        keystone = keystone_connect(username,password)
        if keystone:
            break
        else:
            print('Authentication error, check your username/password')
            continue
        
    #swift options
    swift_options['os_username'] = username
    swift_options['os_password'] = password

    while True:
        choice = input('Make your choice:\n'+
                       '0. Show Swift/S3 usage report\n'+
                       '1. Create Swift/S3 account\n'+
                       '2. Manage Swift/S3 account quota\n'+
                       '3. Enable/Disable Swift/S3 account\n'+
                       '4. Delete Swift/S3 account\n'+
                       '5. Exit script\n')
        if choice == '0':
            print_report(projects_report(keystone))
        elif choice == '1':
            report = PrettyTable(['Parameter','Value'])
            org = input('Enter new account name:\n')
            report.add_row(['Account name',org])
            org_description = input('Enter account description:\n')
            report.add_row(['Account description',org_description])
            quota = int(input('Enter account Swift/S3 quota in Gb:\n')) * 1073741824
            report.add_row(['Account Quota, Gb', quota/1073741824])
            print('Creating account...\t', end='')
            project = project_create(keystone,org,description=org_description)
            if project:
                print('Done\nSetting quota...\t', end='')
                if swift_update_quota(project.name,quota):
                    print('Done\n')
                else:
                    print('Qutoa set failed')
            else:
                print('Project creation failed\n')
                continue
            #create user if needed
            if input('Would you lilke to create a user for {} account?\n'.format(project.name)) in ['y','Y']:
                org_admin = input('Enter OrgAdmin username:\n')
                report.add_row(['User name',org_admin])
                org_admin_passwd = input('Enter OrgAdmin password (leave blank to auto-generate):\n')
                if not org_admin_passwd:
                    org_admin_passwd = generate_password(10)
                report.add_row(['User password',org_admin_passwd])
                org_admin_email = input('Enter OrgAdmin e-mail:\n')
                report.add_row(['User e-mail',org_admin_email])
                print('Creaing user...\t', end='')
                user = user_create(keystone,org_admin,org_admin_passwd,
                                   user_email=org_admin_email,
                                   default_project=project)
                if user:
                    print('Done\nMappin user {} to account {} as user...\t'.format(user.name,project.name), end='')
                else:
                    print('User creation failed\n')
                    continue
                if user_role_add(keystone,user,project):
                    print('Done')
                else:
                    print('Fail')
                print('Creating EC2 keys...\t', end='')
                try:
                    ec2_cred = keystone.ec2.create(user.id,project.id)
                except:
                    print('Fail')
                    continue
                print('Done')
                report.add_row(['S3 Access key', ec2_cred.access])
                report.add_row(['S3 Secret key', ec2_cred.secret])
                
            print(report)
                      
        elif choice == '2':
            org = input('Enter account name:\n')
            try:
                project = keystone.projects.find(name=org)
            except keystoneauth1.exceptions.http.NotFound:
                print('No project {} found. Try again.'.format(org))
                continue
            current_quotas = swift_get_quotas(project.name)
            print('Current quota is {} Gb, Usage is {} Gb\n'.format(current_quotas['quota'],
                                                                    current_quotas['quota_used']))
            quota = int(input('Enter new account Swift/S3 quota in Gb:\n')) * 1073741824
            print('Setting quota...\t', end='')
            if swift_update_quota(project.name, quota):
                print('Done. Quota for {} is {} Gb.\n'.format(project.name,quota / 1073741824))
            else:
                print('Fail. Something went wrong... Dunno why.')
                
        elif choice == '3':
            org = input('Enter account name:\n')
            try:
                project = keystone.projects.find(name=org)
            except keystoneauth1.exceptions.http.NotFound:
                print('No account {} found. Try again.\n'.format(org))
                continue
            if project.enabled:
                choice = input('Account {} is enabled. Would you like to disable it? (Y/N)\n'.format(project.name))
                if choice in ['y','Y']:
                    project.update(enabled=False)
                    print('Accpunt {} disabled'.format(project.name))
                else:
                    continue
            elif not project.enabled:
                choice = input('Account {} is disabled. Would you like to enable it? (Y/N)\n'.format(project.name))
                if choice in ['y','Y']:
                    project.update(enabled=True)
                    print('Accpunt {} enabled'.format(project.name))
                else:
                    continue
        elif choice == '4':
            org = input('Enter account name:\n')
            try:
                project = keystone.projects.find(name=org)
            except keystoneauth1.exceptions.http.NotFound:
                print('No account {} found. Try again.\n'.format(org))
                continue
            if project.name in ['admin','service']:
                print('Cannot remove service account.')
                continue
            if project.enabled:
                print('Error. Account {} is active. Disable to proceed.'.format(project.name))
                continue
            else:
                print('You are about to delete account:')
                #enable project for report, make report on project, diable project.
                project.update(enabled=True)
                print_report(projects_report(keystone,project=project))
                project.update(enabled=False)
                if input("This will remove account and all it's data.\n"+
                         "Are you sure?(yes/no)\n") in ['yes','Yes','YES']:
                    users = get_project_users(keystone,project)
                    print('Deleting account {}...\t'.format(project.name), end='')
                    if project.delete():
                        print('Done')
                    for user in users:
                        if input('Do you want to remove user {}, '.format(user.name) +
                                 'wich was assigned to account?(yes/no)\n') in ['yes','Yes','YES']:
                            print('Deleting user {}...\t'.format(user.name), end='')
                            projects = get_user_projects(keystone,user)
                            if projects:
                                print('Scipping: ', end='')
                                for p in projects:
                                    print('User {} still has a role in other account ({})'.format(user.name,p.name))
                            else:
                                user.delete()
                                print('Done')
                else:
                    print('Account delete canceled!')
                                
        elif choice == '5':
            print('Bye!')
            break
        else:
            print('Invalid choice')
            continue
 

if __name__ == '__main__':
    menu()

