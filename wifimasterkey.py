#!/usr/bin/env python
# -*- coding: utf-8 -*-
#author Vision_lsm

import md5
from Crypto.Cipher import AES
import requests
import random
import urllib
import re

class WifiMasterKey:
	aesKey = 'k%7Ve#8Ie!5Fb&8E'
	aesIV = 'y!0Oe#2Wj#6Pw!3V'
	aesMode = AES.MODE_CBC

	dhid = ''
	mac = ''
	ii = ''

	salt = ''#from server

	def __init__(self):
		self.RegisterNewDevice()

	def __sign(self, data, salt):
		request_str = unicode("",'utf-8')
		for key in sorted(data):
			request_str += data[key].decode('utf-8')
		return md5.md5(request_str + salt).hexdigest().upper()

	def __decrypt(self, ciphertext):
		#[length][password][timestamp]
		decryptor = AES.new(self.aesKey, self.aesMode, IV=self.aesIV)
		return decryptor.decrypt(ciphertext.decode('hex')).strip()[3:-13]

	def RegisterNewDevice(self):
		salt = '1Hf%5Yh&7Og$1Wh!6Vr&7Rs!3Nj#1Aa$'
		data = {}
		data['appid'] = '0008'
		data['chanid'] = 'gw'
		data['ii'] = md5.md5(str(random.randint(1,10000))).hexdigest()
		data['imei'] = data['ii']
		data['lang'] = 'cn'
		data['mac'] = data['ii'][:12]#md5.md5(str(random.randint(1,10000))).hexdigest()[:12]
		data['manuf'] = 'Apple'
		data['method'] = 'getTouristSwitch'
		data['misc'] = 'Mac OS'
		data['model'] = '10.10.3'
		data['os'] = 'Mac OS'
		data['osver'] = '10.10.3'
		data['osvercd'] = '10.10.3'
		data['pid'] = 'initdev:commonswitch'
		data['scrl'] = '813'
		data['scrs'] = '1440'
		data['wkver'] = '324'
		data['st'] = 'm'
		data['v'] = '324'
		data['sign'] = self.__sign(data, salt)

		url = 'http://wifiapi02.51y5.net/wifiapi/fa.cmd'

		useragent = 'WiFiMasterKey/1.1.0 (Mac OS X Version 10.10.3 (Build 14D136))'
		headers = {'User-Agent': useragent}

		r = requests.post(url, data=data, headers=headers).json()

		if r['retCd'] == '0' and r['initdev']['retCd'] == '0':
			self.imei = data['imei']
			self.ii = data['ii']
			self.mac = data['mac']
			self.dhid = r['initdev']['dhid']
			self.salt = salt
			return True
		else:
			return False

	def __query(self, ssid, bssid):
		data = {}
		data['appid'] = '0008'
		data['bssid'] = ','.join(bssid)
		data['chanid'] = 'gw'
		data['dhid'] = self.dhid
		data['ii'] = self.ii
		data['lang'] = 'cn'
		data['mac'] = self.mac
		#data['method'] = 'getSecurityCheckSwitch'
		data["method"] = "getDeepSecChkSwitch"
		#data['pid'] = 'qryapwithoutpwd:commonswitch'
		data["pid"] = "qryapwd:commonswitch"
		data['ssid'] = ','.join(ssid)
		data['st'] = 'm'
		data['uhid'] = 'a0000000000000000000000000000001'
		data['v'] = '324'
		data['sign'] = self.__sign(data, self.salt)

		url = 'http://wifiapi02.51y5.net/wifiapi/fa.cmd'

		useragent = 'WiFiMasterKey/1.1.0 (Mac OS X Version 10.10.3 (Build 14D136))'
		headers = {'User-Agent': useragent}

		r = requests.post(url, data=data, headers=headers).json()
		return r
	
	def query(self, ssid, bssid):
		result = self.__query(ssid, bssid)
		if result['retCd'] == '-1111':
			print result["retMsg"]
			print "retry"
			self.salt = result['retSn']
			result = self.__query(ssid, bssid)
			
		return self.packup(result)
			

	def packup(self, result):
		package = {}
		for info in result["qryapwd"]["psws"]:
			ap = {}
			ap['ssid'] = result["qryapwd"]["psws"][info]["ssid"]
			ap['bssid'] = result["qryapwd"]["psws"][info]["bssid"]
			ap['password'] = self.__decrypt(result["qryapwd"]["psws"][info]["pwd"])
			package[info] = ap
		return package

def main():
	
	ssids = []
	bssids = []

	def add_ap(ssid, bssid):
		ssids.append(ssid)
		bssids.append(bssid)

	wmk = WifiMasterKey()

	pattern_bssid = re.compile(r"BSS (.+?)\(on ")
	pattern_ssid = re.compile(r"SSID: (.+?)\n")
	with open('iwwlan0scan.txt', 'r') as f:	
		text = f.read()
		bssid = pattern_bssid.findall(text)
		ssid = pattern_ssid.findall(text)
	for index in range(len(bssid)):
		#print bssid[index], ssid[index]
		add_ap(ssid[index], bssid[index])
	# Add BSSID & SSID
	#add_ap("4201", "96:0C:6D:59:52:80")
	#add_ap("TP-LINK_DFFC", "EC:26:CA:4A:DF:FC")
	
	packages = wmk.query(ssids,bssids)
	for bssid in packages:
		ap = packages[bssid]
		print "ssid", ap['ssid']
		print "bssid", ap['bssid']
		print "password", urllib.unquote(ap['password'])
		print

	#for ss, bss, dummy in re.compile(pattern, re.M).findall(output):
	#	ssid.append(ss)
	#	bssid.append(bss)

	#wifi().query(ssid, bssid)

if __name__ == '__main__':
	main()
