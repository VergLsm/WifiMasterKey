#!/usr/bin/env python
# -*- coding: utf-8 -*-
#author Vision_lsm

import re
import os
import urllib
import wifimasterkey

class Scanner:

	def findall(self, text):
		pattern_bssid = re.compile(r"BSS (.+?)\(on ")
		pattern_ssid = re.compile(r"SSID: (.*?)\n")
		bssid = pattern_bssid.findall(text)
		ssid = pattern_ssid.findall(text)
		aplist = {}
		for index in range(len(bssid)):
			ap = {}
			ap['ssid'] = ssid[index]
			aplist[bssid[index]] = ap
		return aplist

	def getFileText(self, fileName):
		with open(fileName, 'r') as f:	
			text = f.read()
		return text

	def getLoacl(self):
		output = os.popen('sudo iw wlp3s0 scan')
		return output.read()
	
	def printAll(self, aplist):
		for bssid in aplist:
			print bssid, aplist[bssid]['ssid']
		
def main():
	scanner = Scanner()
	#text = scanner.getFileText('iwwlan0scan.txt')
	text = scanner.getLoacl()
	aplist = scanner.findall(text)
	#scanner.printAll(aplist)
	
	ssids = []
	bssids = []

	def add_ap(ssid, bssid):
		ssids.append(ssid)
		bssids.append(bssid)

	wmk = wifimasterkey.WifiMasterKey()

	for bssid in aplist:
		add_ap(aplist[bssid]['ssid'], bssid)  
	
	packages = wmk.query(ssids,bssids)
	for bssid in packages:
		ap = packages[bssid]
		print "ssid", ap['ssid']
		print "bssid", ap['bssid']
		print "password", urllib.unquote(ap['password'])
		print

if __name__ == '__main__':
	main()
