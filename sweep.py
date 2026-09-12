import subprocess

network = "192.168.1."

for host in range(1, 255):
	ip = network +str(host)
	result = subprocess.run(
		["ping", "-c", "1", "-W", "1",ip],
		stdout = subprocess.DEVNULL,
		stderr = subprocess.DEVNULL
	)
	if result.returncode == 0:
		print(ip, "is up")
