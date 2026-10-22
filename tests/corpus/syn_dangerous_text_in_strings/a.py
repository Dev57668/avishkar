"""Never call eval(x) or os.system(c); do not pass verify=False or shell=True."""
# pickle.loads(data) is unsafe; hashlib.md5 too
NOTE = 'subprocess.run(c, shell=True) is dangerous'
RX = r'verify\s*=\s*False'
